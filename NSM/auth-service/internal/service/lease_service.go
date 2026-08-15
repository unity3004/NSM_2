package service

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/leasing"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/policy"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// Permission strings LeaseService checks — leases is its own resource,
// deliberately separate from secrets:* (see migrations/000031's own doc
// comment): a role that can read static secrets must not automatically
// be able to issue dynamic credentials.
const (
	permLeasesCreate = "leases:create"
	permLeasesRead   = "leases:read"
	permLeasesRevoke = "leases:revoke"
)

var (
	// ErrUnknownLeaseType means a lease-creation request named a "type"
	// no DynamicCredentialProvider is registered under.
	ErrUnknownLeaseType = errors.New("service: no dynamic-credential provider is registered for this lease type")
	// ErrLeaseNotRenewable means Renew was called on a lease created with
	// Renewable=false.
	ErrLeaseNotRenewable = errors.New("service: this lease is not renewable")
	// ErrLeaseNotActive covers both a revoked and an expired lease — the
	// same "one generic outcome, never revealing which specific state it
	// was in" shape entity.ErrInvalidServiceAccountCredential's own doc
	// comment gives for machine-auth failures, for the identical
	// anti-enumeration reason.
	ErrLeaseNotActive = errors.New("service: this lease is not active")
	// ErrLeaseRenewalExceedsMaxLifetime means this lease has already
	// reached its configured MaxRenewableLifetime — there is no
	// remaining window left to grant, so Renew refuses outright rather
	// than silently granting a zero-or-negative extension.
	ErrLeaseRenewalExceedsMaxLifetime = errors.New("service: this lease has reached its maximum renewable lifetime")
)

// LeaseIdentity names the caller a lease-lifecycle method acts as or on
// behalf of — the same {Type, ID} shape entity.LeaseOwnerType/OwnerIdentityID
// already carry on the persisted row, so an ownership comparison is
// always a direct, unambiguous struct-field match, never a bare ID
// string compared without also knowing which identity space it names.
type LeaseIdentity struct {
	Type entity.LeaseOwnerType
	ID   string
}

// LeaseServiceDeps wires LeaseService's dependencies. TTL fields are
// plain values (config.LeaseConfig's own fields, sourced by
// cmd/server/main.go) rather than a config.Config dependency — the same
// "pass the values a service needs directly, never the whole config
// package" convention RefreshTokenServiceDeps.RefreshTTL already
// establishes.
type LeaseServiceDeps struct {
	Leases   repository.LeaseRepository
	RBAC     *RBACService
	Policies *SecretPolicyService
	// Providers is the DynamicCredentialProvider registry, keyed by
	// Provider.Type() — see leasing.DynamicCredentialProvider's own doc
	// comment. cmd/server/main.go registers leasing.NewDevCredentialProvider()
	// under "dev-credential" today; a future production provider adds a
	// second map entry, never a change to this service's own code.
	Providers map[string]leasing.DynamicCredentialProvider
	MinTTL    time.Duration
	DefaultTTL,
	MaxTTL,
	MaxRenewableLifetime time.Duration
	AuditTx AuditTxFunc
}

// LeaseService orchestrates Sprint 5 Task 2's dynamic-secret lease
// lifecycle: authorization, TTL clamping, credential generation (via a
// registered leasing.DynamicCredentialProvider), and durable persistence
// (repository.LeaseRepository) — deliberately a separate model from
// SecretService's static, encrypted-at-rest secrets, never layered on
// top of it. A lease's "resource" is a path in the same normalized
// namespace static secret paths use (util.NormalizeSecretPath/
// ValidateSecretPath, and the same SecretPolicyService path-policy engine
// governs it), but a lease path need not — and typically does not — name
// an actual secrets/secret_versions row: dynamic-secret "mounts" are
// their own namespace, the same way Vault's KV and database secrets
// engines share a policy syntax without sharing storage.
//
// Every method that mutates a lease's lifecycle records an audit event
// itself (see recordLeaseAudit/recordSystemLeaseAudit) — best-effort,
// the same convention every other service in this codebase already
// follows.
type LeaseService struct {
	deps LeaseServiceDeps
}

func NewLeaseService(deps LeaseServiceDeps) *LeaseService {
	return &LeaseService{deps: deps}
}

// CreateLeaseInput is Create's argument.
type CreateLeaseInput struct {
	OrganizationID string
	LeaseType      string
	ResourcePath   string
	// RequestedTTL is the caller's request — zero means "use
	// DefaultTTL," never "unlimited" (see effectiveTTL's own doc
	// comment).
	RequestedTTL time.Duration
	Renewable    bool
	// Role is forwarded to leasing.CreateCredentialInput.Role verbatim —
	// see that field's own doc comment. LeaseService never inspects,
	// validates, or interprets it; DevCredentialProvider ignores it,
	// leasing/postgres.Provider requires it to name one of its own
	// configured role templates (Sprint 5 Task 3).
	Role      string
	Actor     LeaseIdentity
	IPAddress string
}

// CreateLeaseResult carries the one and only response that ever includes
// the raw credential — see leasing.Credential's own doc comment.
type CreateLeaseResult struct {
	Lease      *entity.Lease
	Credential leasing.Credential
}

// Create implements the objective's own authorization chain exactly:
// Authentication (trusted — the caller already resolved in.Actor from a
// verified token) -> Identity -> Global permission (secrets:read, the
// same base gate SecretService.authorize already checks — a lease is
// still fundamentally about reaching a path in the secret-path
// namespace) -> Path policy (SecretPolicyService.Authorize, action=read,
// against the canonical resource path) -> Lease permission
// (leases:create, this task's own additional, explicit gate) ->
// Credential generation.
//
// FAILURE SAFETY: if the provider successfully mints a credential but
// persisting the lease row then fails, this method issues a
// best-effort compensating RevokeCredential call before returning —
// never leaving an unmanaged, unrevoked credential behind (the
// objective's own explicit requirement). Both outcomes are logged loudly
// so an operator can reconcile if the compensating revoke itself fails.
func (s *LeaseService) Create(ctx context.Context, in CreateLeaseInput) (*CreateLeaseResult, error) {
	provider, ok := s.deps.Providers[in.LeaseType]
	if !ok {
		return nil, ErrUnknownLeaseType
	}

	canonicalPath := util.NormalizeSecretPath(in.ResourcePath)
	if err := util.ValidateSecretPath(canonicalPath); err != nil {
		return nil, err
	}

	if err := s.authorizeCreate(ctx, in.Actor, canonicalPath, in.OrganizationID); err != nil {
		s.recordCreateDenied(ctx, in.Actor, canonicalPath, in.IPAddress)
		return nil, err
	}

	ttl := s.effectiveTTL(in.RequestedTTL)
	now := time.Now()
	expiresAt := now.Add(ttl)

	cred, err := provider.CreateCredential(ctx, leasing.CreateCredentialInput{ResourcePath: canonicalPath, TTL: ttl, Role: in.Role})
	if err != nil {
		s.recordCreationFailed(ctx, in.Actor, canonicalPath, in.LeaseType, in.IPAddress)
		return nil, err
	}

	var providerRef *string
	if cred.ProviderRef != "" {
		providerRef = &cred.ProviderRef
	}
	lease := &entity.Lease{
		OrganizationID:    in.OrganizationID,
		LeaseType:         in.LeaseType,
		ResourcePath:      canonicalPath,
		OwnerIdentityType: in.Actor.Type,
		OwnerIdentityID:   in.Actor.ID,
		Status:            entity.LeaseStatusActive,
		Renewable:         in.Renewable,
		TTL:               ttl,
		MaxTTL:            s.deps.MaxTTL,
		ExpiresAt:         expiresAt,
		ProviderRef:       providerRef,
		Metadata:          cred.Metadata,
	}
	if err := s.deps.Leases.Create(ctx, lease); err != nil {
		if revokeErr := provider.RevokeCredential(ctx, cred.ProviderRef); revokeErr != nil {
			logging.FromContext(ctx).Error("lease persistence failed AND compensating credential revocation also failed — "+
				"an unmanaged dynamic credential may exist and needs manual operator reconciliation",
				zap.String("lease_type", in.LeaseType), zap.String("provider_ref", cred.ProviderRef),
				zap.Error(err), zap.NamedError("revoke_error", revokeErr))
		} else {
			logging.FromContext(ctx).Warn("lease persistence failed; compensating credential revocation succeeded",
				zap.String("lease_type", in.LeaseType), zap.Error(err))
		}
		return nil, err
	}

	s.recordLeaseAudit(ctx, "lease.created", in.Actor, lease, in.IPAddress, map[string]any{
		"lease_type": lease.LeaseType, "resource_path": lease.ResourcePath, "ttl_seconds": int(ttl.Seconds()), "renewable": lease.Renewable,
	})
	s.recordLeaseAudit(ctx, "dynamic_credential.created", in.Actor, lease, in.IPAddress, map[string]any{"lease_type": lease.LeaseType})

	return &CreateLeaseResult{Lease: lease, Credential: cred}, nil
}

// Get returns lease metadata — never credential material (entity.Lease
// has no field it could occupy). Callable by the lease's own owner or a
// caller holding leases:read; anyone else is reported entity.ErrNotFound,
// never entity.ErrForbidden — the same anti-enumeration "don't reveal
// that a lease with this ID exists at all" rule GetSecret's own doc
// comment already establishes for secret paths.
//
// The returned lease's Status reflects IsExpired at read time even if
// the persisted row still says LeaseStatusActive (the cleanup worker
// hasn't reached it yet) — an in-memory-only correction on the returned
// value, never an extra write on every read; see entity.Lease.IsExpired's
// own doc comment on why a caller must never trust a stale Active status.
func (s *LeaseService) Get(ctx context.Context, leaseID string, actor LeaseIdentity, ipAddress string) (*entity.Lease, error) {
	lease, err := s.deps.Leases.GetByID(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	if !s.isOwner(lease, actor) {
		allowed, err := s.hasPermission(ctx, actor, permLeasesRead)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, entity.ErrNotFound
		}
	}
	if lease.Status == entity.LeaseStatusActive && lease.IsExpired(time.Now()) {
		lease.Status = entity.LeaseStatusExpired
	}
	s.recordLeaseAudit(ctx, "lease.read", actor, lease, ipAddress, nil)
	return lease, nil
}

// List returns leases visible to actor: every lease in organizationID if
// actor holds leases:read, otherwise only actor's own.
func (s *LeaseService) List(ctx context.Context, organizationID string, actor LeaseIdentity, f repository.LeaseFilter) ([]*entity.Lease, error) {
	allowed, err := s.hasPermission(ctx, actor, permLeasesRead)
	if err != nil {
		return nil, err
	}
	if !allowed {
		f.OwnerIdentityType = &actor.Type
		f.OwnerIdentityID = &actor.ID
	}
	return s.deps.Leases.List(ctx, organizationID, f)
}

// Renew extends a renewable, currently-usable lease's TTL — owner-only,
// deliberately with no administrator bypass (see migrations/000031's own
// doc comment on why there is no leases:renew permission at all):
// renewal is a self-service continuation of a lease the caller itself
// holds, not an action performed on someone else's behalf. Refuses
// ErrLeaseNotActive if the lease is revoked or (per entity.Lease.IsExpired,
// checked here directly, never trusting a possibly-stale Status column —
// the objective's own "authorization must also check expiration" rule)
// already expired, and ErrLeaseNotRenewable if it was never created with
// Renewable=true.
//
// The newly granted window is clamped twice: to at most MaxTTL from now
// (the same per-request ceiling Create applies), and — independently —
// so total lifetime measured from the lease's original CreatedAt never
// exceeds MaxRenewableLifetime, even across many renewals each
// individually within MaxTTL. Refuses ErrLeaseRenewalExceedsMaxLifetime
// if that lifetime is already exhausted; otherwise silently clamps down
// to whatever window remains, the same "never error merely for
// requesting too much, only for having nothing left to grant" philosophy
// effectiveTTL already applies to Create.
func (s *LeaseService) Renew(ctx context.Context, leaseID string, requestedTTL time.Duration, actor LeaseIdentity, ipAddress string) (*entity.Lease, error) {
	lease, err := s.deps.Leases.GetByID(ctx, leaseID)
	if err != nil {
		return nil, err
	}
	if !s.isOwner(lease, actor) {
		return nil, entity.ErrNotFound
	}

	now := time.Now()
	if !lease.IsUsable(now) {
		return nil, ErrLeaseNotActive
	}
	if !lease.Renewable {
		return nil, ErrLeaseNotRenewable
	}

	ttl := s.effectiveTTL(requestedTTL)
	newExpiresAt := now.Add(ttl)

	maxLifetimeExpiresAt := lease.CreatedAt.Add(s.deps.MaxRenewableLifetime)
	if !maxLifetimeExpiresAt.After(now) {
		return nil, ErrLeaseRenewalExceedsMaxLifetime
	}
	if newExpiresAt.After(maxLifetimeExpiresAt) {
		newExpiresAt = maxLifetimeExpiresAt
		ttl = newExpiresAt.Sub(now)
	}

	if provider, ok := s.deps.Providers[lease.LeaseType]; ok && lease.ProviderRef != nil {
		if err := provider.RenewCredential(ctx, *lease.ProviderRef, ttl); err != nil {
			return nil, err
		}
	}

	if err := s.deps.Leases.Renew(ctx, leaseID, ttl, newExpiresAt); err != nil {
		return nil, err
	}
	lease.TTL = ttl
	lease.ExpiresAt = newExpiresAt

	s.recordLeaseAudit(ctx, "lease.renewed", actor, lease, ipAddress, map[string]any{
		"ttl_seconds": int(ttl.Seconds()),
	})
	return lease, nil
}

// Revoke transitions a lease to LeaseStatusRevoked — callable by the
// lease's own owner or a caller holding leases:revoke (the objective's
// own "lease owner OR authorized administrator" rule), reported
// entity.ErrNotFound for anyone else, the same anti-enumeration
// convention Get already follows. Idempotent: revoking an
// already-revoked or already-expired lease is a no-op (LeaseRepository.Revoke's
// own WHERE status = 'active' guard) that returns nil without a second
// audit entry — the identical "transition-only, never one event per
// repeated call" bound rate-limit's own audit convention already
// establishes.
//
// Best-effort calls the owning provider's RevokeCredential after the
// database transition succeeds — a provider-side failure is logged
// loudly (an operator reconciliation signal) but never changes the
// already-committed revoked status: from this service's own authorization
// boundary, a revoked lease is unusable regardless of whether the
// underlying external credential was also successfully torn down.
func (s *LeaseService) Revoke(ctx context.Context, leaseID, reason string, actor LeaseIdentity, ipAddress string) error {
	lease, err := s.deps.Leases.GetByID(ctx, leaseID)
	if err != nil {
		return err
	}
	if !s.isOwner(lease, actor) {
		allowed, err := s.hasPermission(ctx, actor, permLeasesRevoke)
		if err != nil {
			return err
		}
		if !allowed {
			return entity.ErrNotFound
		}
	}

	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	transitioned, err := s.deps.Leases.Revoke(ctx, leaseID, reasonPtr, time.Now())
	if err != nil {
		return err
	}
	if !transitioned {
		return nil
	}

	if provider, ok := s.deps.Providers[lease.LeaseType]; ok && lease.ProviderRef != nil {
		if err := provider.RevokeCredential(ctx, *lease.ProviderRef); err != nil {
			logging.FromContext(ctx).Error("lease revoked in the database, but the underlying provider credential revocation failed — "+
				"needs manual operator reconciliation", zap.String("lease_id", leaseID), zap.Error(err))
			s.recordLeaseAuditFailure(ctx, "dynamic_credential.revocation_failed", actor, lease, ipAddress, map[string]any{"error": err.Error()})
		}
	}

	s.recordLeaseAudit(ctx, "lease.revoked", actor, lease, ipAddress, map[string]any{"reason": reason})
	s.recordLeaseAudit(ctx, "dynamic_credential.revoked", actor, lease, ipAddress, nil)
	return nil
}

// ExpireOverdue is the cleanup worker's own entry point (see
// cmd/server/main.go's background ticker) — the database-level half of
// expiration enforcement described on entity.Lease.IsExpired's own doc
// comment. Revokes each newly-expired lease's underlying provider
// credential best-effort and records one bounded "lease.expired" audit
// event per lease, attributed to entity.AuditActorSystem (nothing a human
// or service account did caused this transition).
func (s *LeaseService) ExpireOverdue(ctx context.Context) (int, error) {
	expired, err := s.deps.Leases.ExpireOverdue(ctx, time.Now())
	if err != nil {
		return 0, err
	}
	for _, lease := range expired {
		if provider, ok := s.deps.Providers[lease.LeaseType]; ok && lease.ProviderRef != nil {
			if err := provider.RevokeCredential(ctx, *lease.ProviderRef); err != nil {
				logging.FromContext(ctx).Error("failed to revoke underlying provider credential for an expired lease during cleanup",
					zap.String("lease_id", lease.ID), zap.Error(err))
				s.recordSystemLeaseAuditFailure(ctx, "dynamic_credential.revocation_failed", lease, map[string]any{"error": err.Error()})
			}
		}
		s.recordSystemLeaseAudit(ctx, "lease.expired", lease)
		s.recordSystemLeaseAudit(ctx, "dynamic_credential.expired", lease)
	}
	return len(expired), nil
}

// --- authorization helpers ---

func (s *LeaseService) isOwner(lease *entity.Lease, actor LeaseIdentity) bool {
	return lease.OwnerIdentityType == actor.Type && lease.OwnerIdentityID == actor.ID
}

func (s *LeaseService) hasPermission(ctx context.Context, actor LeaseIdentity, permission string) (bool, error) {
	if actor.Type == entity.LeaseOwnerServiceAccount {
		return s.deps.RBAC.HasServiceAccountPermission(ctx, actor.ID, permission)
	}
	return s.deps.RBAC.HasPermission(ctx, actor.ID, permission)
}

// authorizeCreate implements the three-step chain Create's own doc
// comment describes.
func (s *LeaseService) authorizeCreate(ctx context.Context, actor LeaseIdentity, canonicalPath, organizationID string) error {
	if actor.ID == "" {
		return entity.ErrForbidden
	}
	isServiceAccount := actor.Type == entity.LeaseOwnerServiceAccount

	allowed, err := s.hasPermission(ctx, actor, permSecretsRead)
	if err != nil {
		return err
	}
	if !allowed {
		return entity.ErrForbidden
	}

	allowed, err = s.deps.Policies.Authorize(ctx, actor.ID, isServiceAccount, organizationID, canonicalPath, policy.ActionRead)
	if err != nil {
		return err
	}
	if !allowed {
		return entity.ErrForbidden
	}

	allowed, err = s.hasPermission(ctx, actor, permLeasesCreate)
	if err != nil {
		return err
	}
	if !allowed {
		return entity.ErrForbidden
	}
	return nil
}

// effectiveTTL clamps a caller-requested TTL to [MinTTL, MaxTTL],
// defaulting to DefaultTTL when requested is zero — mirrors the
// objective's own worked example (requested 4h, maximum 1h -> effective
// 1h) exactly: this never errors for requesting too much, it only ever
// silently grants less. requested <= 0 is always treated as "use
// DefaultTTL" — dto.LeaseCreateRequest.Validate is what rejects an
// explicitly-supplied non-positive TTL string as a malformed request
// before it ever reaches this method (see that type's own doc comment);
// by the time RequestedTTL reaches here, zero unambiguously means
// "omitted."
func (s *LeaseService) effectiveTTL(requested time.Duration) time.Duration {
	ttl := requested
	if ttl <= 0 {
		ttl = s.deps.DefaultTTL
	}
	if ttl < s.deps.MinTTL {
		ttl = s.deps.MinTTL
	}
	if ttl > s.deps.MaxTTL {
		ttl = s.deps.MaxTTL
	}
	return ttl
}

// --- audit ---

func (s *LeaseService) recordCreateDenied(ctx context.Context, actor LeaseIdentity, canonicalPath, ipAddress string) {
	if s.deps.AuditTx == nil {
		return
	}
	actorType := entity.AuditActorUser
	if actor.Type == entity.LeaseOwnerServiceAccount {
		actorType = entity.AuditActorServiceAccount
	}
	actorID := actor.ID
	err := s.deps.AuditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    actorType,
			ActorID:      &actorID,
			Action:       "lease.create_denied",
			ResourceType: strPtr("lease"),
			ResourceID:   strPtr(canonicalPath),
			Result:       entity.AuditResultDenied,
			IPAddress:    strPtr(ipAddress),
			RequestID:    strPtr(util.RequestIDFromContext(ctx)),
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record lease.create_denied audit event", zap.Error(err))
	}
}

// recordCreationFailed is Create's own audit write for a provider-side
// minting failure (Sprint 5 Task 3's own "dynamic_credential.creation_failed"
// event) — recorded against canonicalPath, not a lease ID, since no
// entity.Lease row exists yet at this point in Create (the provider call
// happens before persistence).
func (s *LeaseService) recordCreationFailed(ctx context.Context, actor LeaseIdentity, canonicalPath, leaseType, ipAddress string) {
	if s.deps.AuditTx == nil {
		return
	}
	actorType := entity.AuditActorUser
	if actor.Type == entity.LeaseOwnerServiceAccount {
		actorType = entity.AuditActorServiceAccount
	}
	actorID := actor.ID
	err := s.deps.AuditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    actorType,
			ActorID:      &actorID,
			Action:       "dynamic_credential.creation_failed",
			ResourceType: strPtr("lease"),
			ResourceID:   strPtr(canonicalPath),
			Result:       entity.AuditResultFailure,
			IPAddress:    strPtr(ipAddress),
			RequestID:    strPtr(util.RequestIDFromContext(ctx)),
			Metadata:     map[string]any{"lease_type": leaseType},
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record dynamic_credential.creation_failed audit event", zap.Error(err))
	}
}

// recordLeaseAudit is every owner/administrator-attributed lease event's
// audit write — ActorType is derived from actor, the caller who actually
// performed the action (contrast recordSystemLeaseAudit, for transitions
// nobody requested). Best-effort, the same convention every other audit
// write in this codebase already follows.
func (s *LeaseService) recordLeaseAudit(ctx context.Context, action string, actor LeaseIdentity, lease *entity.Lease, ipAddress string, metadata map[string]any) {
	if s.deps.AuditTx == nil {
		return
	}
	actorType := entity.AuditActorUser
	if actor.Type == entity.LeaseOwnerServiceAccount {
		actorType = entity.AuditActorServiceAccount
	}
	actorID := actor.ID
	orgID := lease.OrganizationID
	err := s.deps.AuditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: &orgID,
			ActorType:      actorType,
			ActorID:        &actorID,
			Action:         action,
			ResourceType:   strPtr("lease"),
			ResourceID:     strPtr(lease.ID),
			Result:         entity.AuditResultSuccess,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record lease audit event", zap.String("action", action), zap.Error(err))
	}
}

// recordLeaseAuditFailure is recordLeaseAudit's Result:
// entity.AuditResultFailure sibling — Revoke's own
// "dynamic_credential.revocation_failed" event (Sprint 5 Task 3), for a
// provider-side revocation that failed after the lease's own database
// transition to revoked already committed (see Revoke's own doc comment
// on why that failure never rolls the transition back).
func (s *LeaseService) recordLeaseAuditFailure(ctx context.Context, action string, actor LeaseIdentity, lease *entity.Lease, ipAddress string, metadata map[string]any) {
	if s.deps.AuditTx == nil {
		return
	}
	actorType := entity.AuditActorUser
	if actor.Type == entity.LeaseOwnerServiceAccount {
		actorType = entity.AuditActorServiceAccount
	}
	actorID := actor.ID
	orgID := lease.OrganizationID
	err := s.deps.AuditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: &orgID,
			ActorType:      actorType,
			ActorID:        &actorID,
			Action:         action,
			ResourceType:   strPtr("lease"),
			ResourceID:     strPtr(lease.ID),
			Result:         entity.AuditResultFailure,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record lease audit failure event", zap.String("action", action), zap.Error(err))
	}
}

// recordSystemLeaseAudit is ExpireOverdue's own audit write —
// AuditActorSystem, never attributed to the lease's owner: the owner
// didn't request this transition, the passage of time did.
func (s *LeaseService) recordSystemLeaseAudit(ctx context.Context, action string, lease *entity.Lease) {
	if s.deps.AuditTx == nil {
		return
	}
	orgID := lease.OrganizationID
	err := s.deps.AuditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: &orgID,
			ActorType:      entity.AuditActorSystem,
			Action:         action,
			ResourceType:   strPtr("lease"),
			ResourceID:     strPtr(lease.ID),
			Result:         entity.AuditResultSuccess,
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record system lease audit event", zap.String("action", action), zap.Error(err))
	}
}

// recordSystemLeaseAuditFailure is recordSystemLeaseAudit's Result:
// entity.AuditResultFailure sibling — ExpireOverdue's own
// "dynamic_credential.revocation_failed" event when the best-effort
// provider revoke during cleanup fails (Sprint 5 Task 3): the lease
// itself is already correctly expired in the database either way (see
// ExpireOverdue's own doc comment), this only flags that the underlying
// provider credential may still be usable and needs operator
// reconciliation.
func (s *LeaseService) recordSystemLeaseAuditFailure(ctx context.Context, action string, lease *entity.Lease, metadata map[string]any) {
	if s.deps.AuditTx == nil {
		return
	}
	orgID := lease.OrganizationID
	err := s.deps.AuditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: &orgID,
			ActorType:      entity.AuditActorSystem,
			Action:         action,
			ResourceType:   strPtr("lease"),
			ResourceID:     strPtr(lease.ID),
			Result:         entity.AuditResultFailure,
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record system lease audit failure event", zap.String("action", action), zap.Error(err))
	}
}
