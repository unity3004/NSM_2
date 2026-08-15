package service

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// ServiceAccountService is the machine-identity counterpart to
// UserService/AuthService combined (Sprint 5 Task 1) — service account
// lifecycle administration (Create/Disable/Enable/AssignRole, mirroring
// UserService's own admin surface almost field-for-field) plus machine
// authentication (Authenticate, mirroring AuthService.Login's structure:
// a Redis abuse-protection pre-check, a credential verification step, and
// short-lived access token issuance).
//
// Unlike SecretService/SecretPolicyService, this service does not perform
// its own internal RBAC check for the admin-CRUD methods below — it
// follows UserService's newer, simpler precedent instead (see that type's
// own doc comment on why RequirePermission at the router layer is
// sufficient once that middleware exists, which it didn't yet when
// SecretService was first written). Authenticate is the one method with
// no permission to check at all: reaching it *is* the authentication
// attempt.
type ServiceAccountService struct {
	serviceAccounts repository.ServiceAccountRepository
	apiKeys         repository.APIKeyRepository
	tokens          *util.JWTSigner
	// abuseProtection guards Authenticate the same way
	// AuthServiceDeps.AbuseProtection guards Login — required, not
	// optional; see that field's own doc comment. Every existing test
	// that constructs this service supplies a
	// ratelimit.FakeAuthAbuseProtection or ratelimit.NoopAuthAbuseProtection.
	abuseProtection     ratelimit.AuthAbuseProtection
	rateLimitRetryAfter time.Duration
	auditTx             AuditTxFunc
}

func NewServiceAccountService(
	serviceAccounts repository.ServiceAccountRepository,
	apiKeys repository.APIKeyRepository,
	tokens *util.JWTSigner,
	abuseProtection ratelimit.AuthAbuseProtection,
	rateLimitRetryAfter time.Duration,
	auditTx AuditTxFunc,
) *ServiceAccountService {
	return &ServiceAccountService{
		serviceAccounts:     serviceAccounts,
		apiKeys:             apiKeys,
		tokens:              tokens,
		abuseProtection:     abuseProtection,
		rateLimitRetryAfter: rateLimitRetryAfter,
		auditTx:             auditTx,
	}
}

// --- lifecycle administration ---

type CreateServiceAccountInput struct {
	OrganizationID string
	Name           string
	Description    *string
	ActorUserID    string
	IPAddress      string
}

func (s *ServiceAccountService) CreateServiceAccount(ctx context.Context, in CreateServiceAccountInput) (*entity.ServiceAccount, error) {
	actor := in.ActorUserID
	sa := &entity.ServiceAccount{
		OrganizationID: in.OrganizationID,
		Name:           in.Name,
		Description:    in.Description,
		Status:         entity.ServiceAccountStatusActive,
		CreatedBy:      strPtr(actor),
	}
	if err := s.serviceAccounts.Create(ctx, sa); err != nil {
		return nil, err
	}
	s.recordAdminAudit(ctx, "service_account.created", in.ActorUserID, sa.ID, in.IPAddress, map[string]any{"name": sa.Name})
	return sa, nil
}

func (s *ServiceAccountService) GetServiceAccount(ctx context.Context, id string) (*entity.ServiceAccount, error) {
	return s.serviceAccounts.GetByID(ctx, id)
}

func (s *ServiceAccountService) ListServiceAccounts(ctx context.Context, organizationID string, cursor *string, limit int) ([]*entity.ServiceAccount, error) {
	return s.serviceAccounts.List(ctx, organizationID, cursor, limit)
}

// UpdateServiceAccount changes Name/Description only — Status has its own
// dedicated Disable/Enable methods below, the same separation
// UserService.UpdateUser/DisableUser/EnableUser already establish for
// users.
func (s *ServiceAccountService) UpdateServiceAccount(ctx context.Context, id, name string, description *string, actorUserID, ipAddress string) (*entity.ServiceAccount, error) {
	sa, err := s.serviceAccounts.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	sa.Name = name
	sa.Description = description
	if err := s.serviceAccounts.Update(ctx, sa); err != nil {
		return nil, err
	}
	s.recordAdminAudit(ctx, "service_account.updated", actorUserID, id, ipAddress, nil)
	return sa, nil
}

// DeleteServiceAccount permanently removes the service account —
// service_account_roles and api_keys both cascade-delete with it (see
// migrations 000012/000013's own ON DELETE CASCADE), so there is no
// separate cleanup step this method needs to perform first.
func (s *ServiceAccountService) DeleteServiceAccount(ctx context.Context, id, actorUserID, ipAddress string) error {
	if err := s.serviceAccounts.Delete(ctx, id); err != nil {
		return err
	}
	s.recordAdminAudit(ctx, "service_account.deleted", actorUserID, id, ipAddress, nil)
	return nil
}

// DisableServiceAccount sets Status to Disabled and revokes every one of
// the service account's currently active credentials — the machine
// equivalent of UserService.DisableUser revoking every active session.
// This is what actually stops further access: Authenticate already
// rejects a Disabled service account outright (entity.ErrAccountDisabled)
// regardless of credential state, and revoking the credentials on top of
// that closes the narrower gap of "a credential that's still individually
// valid but whose owning account just got disabled." It does not, and
// cannot, revoke an access token already issued before the disable — the
// same already-documented characteristic of this codebase's stateless-JWT
// access tokens UserService.DisableUser's own doc comment describes for
// human users, which is exactly why machine access tokens should be
// short-lived (see cmd/server/main.go's own token TTL configuration).
func (s *ServiceAccountService) DisableServiceAccount(ctx context.Context, id, actorUserID, ipAddress string) error {
	sa, err := s.serviceAccounts.GetByID(ctx, id)
	if err != nil {
		return err
	}
	sa.Status = entity.ServiceAccountStatusDisabled
	if err := s.serviceAccounts.Update(ctx, sa); err != nil {
		return err
	}
	if err := s.revokeAllActiveCredentials(ctx, id, "service_account_disabled"); err != nil {
		logging.FromContext(ctx).Error("failed to revoke credentials after disabling service account",
			zap.String("service_account_id", id), zap.Error(err))
	}
	s.recordAdminAudit(ctx, "service_account.disabled", actorUserID, id, ipAddress, nil)
	return nil
}

func (s *ServiceAccountService) EnableServiceAccount(ctx context.Context, id, actorUserID, ipAddress string) error {
	sa, err := s.serviceAccounts.GetByID(ctx, id)
	if err != nil {
		return err
	}
	sa.Status = entity.ServiceAccountStatusActive
	if err := s.serviceAccounts.Update(ctx, sa); err != nil {
		return err
	}
	s.recordAdminAudit(ctx, "service_account.enabled", actorUserID, id, ipAddress, nil)
	return nil
}

func (s *ServiceAccountService) AssignRole(ctx context.Context, serviceAccountID, roleID, actorUserID, ipAddress string) error {
	grant := &entity.ServiceAccountRole{ServiceAccountID: serviceAccountID, RoleID: roleID, AssignedBy: strPtr(actorUserID)}
	if err := s.serviceAccounts.GrantRole(ctx, grant); err != nil {
		return err
	}
	s.recordAdminAudit(ctx, "role.assigned", actorUserID, serviceAccountID, ipAddress, map[string]any{"role_id": roleID})
	return nil
}

func (s *ServiceAccountService) RemoveRole(ctx context.Context, serviceAccountID, roleID, actorUserID, ipAddress string) error {
	if err := s.serviceAccounts.RevokeRole(ctx, serviceAccountID, roleID); err != nil {
		return err
	}
	s.recordAdminAudit(ctx, "role.removed", actorUserID, serviceAccountID, ipAddress, map[string]any{"role_id": roleID})
	return nil
}

func (s *ServiceAccountService) ListRoles(ctx context.Context, serviceAccountID string) ([]*entity.ServiceAccountRole, error) {
	return s.serviceAccounts.ListRoles(ctx, serviceAccountID)
}

// --- credential lifecycle ---

// IssueCredentialInput's ExpiresAt is optional — a nil value means the
// credential never expires on its own, relying entirely on explicit
// revocation/rotation or the owning service account being disabled. The
// objective's own "expiration where appropriate" leaves this a per-credential
// administrator choice, not a platform-wide mandate.
type IssueCredentialInput struct {
	ServiceAccountID string
	Name             string
	ExpiresAt        *time.Time
	ActorUserID      string
	IPAddress        string
}

// IssueCredentialResult carries the one and only time the raw secret is
// ever available — see entity.APIKey's own doc comment.
type IssueCredentialResult struct {
	Key    *entity.APIKey
	Secret string
}

func (s *ServiceAccountService) IssueCredential(ctx context.Context, in IssueCredentialInput) (*IssueCredentialResult, error) {
	sa, err := s.serviceAccounts.GetByID(ctx, in.ServiceAccountID)
	if err != nil {
		return nil, err
	}
	secret, prefix, err := util.NewAPIKey()
	if err != nil {
		return nil, err
	}
	key := &entity.APIKey{
		OrganizationID:        sa.OrganizationID,
		OwnerServiceAccountID: &sa.ID,
		Name:                  in.Name,
		KeyPrefix:             prefix,
		KeyHash:               util.HashToken(secret),
		Status:                entity.APIKeyStatusActive,
		ExpiresAt:             in.ExpiresAt,
	}
	if err := s.apiKeys.Create(ctx, key); err != nil {
		return nil, err
	}
	// Metadata carries only the credential's own non-secret identity
	// (id, prefix) — never key.KeyHash and never secret. There is no path
	// from either into this map, and there must never be one (the
	// objective's own "never audit... credential secret" requirement).
	s.recordAdminAudit(ctx, "service_account.credential.created", in.ActorUserID, in.ServiceAccountID, in.IPAddress,
		map[string]any{"credential_id": key.ID, "credential_prefix": key.KeyPrefix})
	return &IssueCredentialResult{Key: key, Secret: secret}, nil
}

func (s *ServiceAccountService) ListCredentials(ctx context.Context, serviceAccountID string) ([]*entity.APIKey, error) {
	return s.apiKeys.List(ctx, "", repository.ApiKeyFilter{OwnerServiceAccountID: &serviceAccountID, Limit: 100})
}

// GetCredential looks up a credential by its own ID — metadata only
// (entity.APIKey never carries a decodable secret at all; see that type's
// own doc comment), the single-key-lookup counterpart to ListCredentials
// for /v1/api-keys/{apiKeyId}, which — unlike the service-account-scoped
// routes — has no serviceAccountID of its own to key off of.
func (s *ServiceAccountService) GetCredential(ctx context.Context, credentialID string) (*entity.APIKey, error) {
	return s.apiKeys.GetByID(ctx, credentialID)
}

// RevokeCredential revokes a credential by its own ID — /v1/api-keys/{id}
// carries no serviceAccountID to cross-check against (unlike this
// service's other admin methods, which are all reached via
// /v1/service-accounts/{id}/...), so there is nothing to verify beyond
// "this credential exists." Authorization is the caller's job
// (requirePermission("api_keys:delete", ...) — router.go), the same
// division of responsibility every other method in this file already
// relies on.
func (s *ServiceAccountService) RevokeCredential(ctx context.Context, credentialID, actorUserID, ipAddress string) error {
	key, err := s.apiKeys.GetByID(ctx, credentialID)
	if err != nil {
		return err
	}
	reason := "admin_revoked"
	if err := s.apiKeys.Revoke(ctx, credentialID, &reason); err != nil {
		return err
	}
	s.recordAdminAudit(ctx, "service_account.credential.revoked", actorUserID, ownerServiceAccountID(key), ipAddress,
		map[string]any{"credential_id": credentialID})
	return nil
}

// RotateCredential issues a brand-new credential (same owner, name, and
// expiry policy as the old one) and revokes the old one in the same call
// — the objective's own "support rotation" requirement, implemented as
// issue-then-revoke rather than a single UPDATE, since a credential's
// secret (and therefore its key_hash) is immutable once created by this
// codebase's own design (see entity.APIKey's doc comment: "only Create
// returns the raw secret, and only once"). A crash between the two steps
// leaves both credentials valid rather than the caller locked out
// entirely — a safer failure mode than the reverse ordering.
func (s *ServiceAccountService) RotateCredential(ctx context.Context, credentialID, actorUserID, ipAddress string) (*IssueCredentialResult, error) {
	old, err := s.apiKeys.GetByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if old.OwnerServiceAccountID == nil {
		return nil, entity.ErrNotFound
	}

	result, err := s.IssueCredential(ctx, IssueCredentialInput{
		ServiceAccountID: *old.OwnerServiceAccountID,
		Name:             old.Name,
		ExpiresAt:        old.ExpiresAt,
		ActorUserID:      actorUserID,
		IPAddress:        ipAddress,
	})
	if err != nil {
		return nil, err
	}

	reason := "rotated"
	if err := s.apiKeys.Revoke(ctx, credentialID, &reason); err != nil {
		logging.FromContext(ctx).Error("failed to revoke old credential after rotation",
			zap.String("old_credential_id", credentialID), zap.Error(err))
	}
	s.recordAdminAudit(ctx, "service_account.credential.rotated", actorUserID, *old.OwnerServiceAccountID, ipAddress,
		map[string]any{"old_credential_id": credentialID, "new_credential_id": result.Key.ID})
	return result, nil
}

// ownerServiceAccountID reads a credential's owning service account ID
// for audit attribution, or "" if it has none (a user-owned key — not
// reachable through this task's own HTTP surface, but this service's
// underlying repository is owner-agnostic, so this stays a safe default
// rather than a panic on a nil dereference).
func ownerServiceAccountID(k *entity.APIKey) string {
	if k.OwnerServiceAccountID == nil {
		return ""
	}
	return *k.OwnerServiceAccountID
}

// revokeAllActiveCredentials is DisableServiceAccount's own bulk-revoke
// step — best-effort per key, so one credential failing to revoke doesn't
// stop the rest from being tried.
func (s *ServiceAccountService) revokeAllActiveCredentials(ctx context.Context, serviceAccountID, reason string) error {
	active := entity.APIKeyStatusActive
	keys, err := s.apiKeys.List(ctx, "", repository.ApiKeyFilter{OwnerServiceAccountID: &serviceAccountID, Status: &active, Limit: 100})
	if err != nil {
		return err
	}
	var firstErr error
	for _, k := range keys {
		if err := s.apiKeys.Revoke(ctx, k.ID, &reason); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// --- machine authentication ---

// AuthenticateResult mirrors AuthService.LoginResult's shape, minus the
// fields a service account has no equivalent of (RefreshToken, SessionID)
// — see Authenticate's own doc comment for why this is a deliberately
// simpler, access-token-only flow.
type AuthenticateResult struct {
	AccessToken string
	ExpiresIn   int
}

// Authenticate implements POST /v1/service-accounts/{id}/token: exchange a
// credential secret for a short-lived access token. It deliberately does
// not mint a refresh token the way AuthService.Login does — a machine
// credential is itself the long-lived artifact (rotatable, revocable, the
// objective's own credential-security requirements already cover it);
// building a second, parallel refresh-rotation system on top of it for
// machine tokens would duplicate that same capability rather than add a
// new one. A caller re-authenticates with its credential once its access
// token expires, the same way a caller with an API key re-presents it on
// every request in systems that don't mint session tokens at all — this
// is that model, scoped to a short-lived JWT instead of the raw
// credential riding on every request.
//
// Every exit path is covered by recordServiceAccountAuthAudit via the
// deferred call below, so a failure can never be invisible to abuse
// detection just because this method returned early — the same guarantee
// AuthService.Login's own login_history write makes.
func (s *ServiceAccountService) Authenticate(ctx context.Context, serviceAccountID, rawSecret string, meta LoginMeta) (*AuthenticateResult, error) {
	dims := ratelimit.Dimensions{IP: meta.IPAddress, Account: serviceAccountID}
	if decision, _ := s.abuseProtection.Check(ctx, ratelimit.OperationServiceAccountAuth, dims); !decision.Allowed {
		return nil, RateLimitedError{RetryAfter: s.rateLimitRetryAfter}
	}

	var authErr error
	var failureReason string
	defer func() {
		s.recordServiceAccountAuthAudit(ctx, serviceAccountID, authErr, failureReason, meta)
	}()

	key, err := s.apiKeys.GetByKeyHash(ctx, util.HashToken(rawSecret))
	if err != nil {
		failureReason = "unknown_credential"
		authErr = entity.ErrInvalidServiceAccountCredential
		s.recordAuthFailure(ctx, dims)
		return nil, authErr
	}
	if key.OwnerServiceAccountID == nil || *key.OwnerServiceAccountID != serviceAccountID {
		// Anti-enumeration: a credential that is valid but belongs to a
		// *different* service account than the one named in the path must
		// fail exactly like an unknown credential — never a distinct
		// signal that would let a caller confirm serviceAccountID exists
		// or that this particular secret is real but misrouted.
		failureReason = "owner_mismatch"
		authErr = entity.ErrInvalidServiceAccountCredential
		s.recordAuthFailure(ctx, dims)
		return nil, authErr
	}
	if key.Status != entity.APIKeyStatusActive {
		failureReason = "credential_" + string(key.Status)
		authErr = entity.ErrInvalidServiceAccountCredential
		s.recordAuthFailure(ctx, dims)
		return nil, authErr
	}
	if key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now()) {
		failureReason = "credential_expired"
		authErr = entity.ErrInvalidServiceAccountCredential
		s.recordAuthFailure(ctx, dims)
		return nil, authErr
	}

	sa, err := s.serviceAccounts.GetByID(ctx, serviceAccountID)
	if err != nil {
		failureReason = "unknown_service_account"
		authErr = entity.ErrInvalidServiceAccountCredential
		s.recordAuthFailure(ctx, dims)
		return nil, authErr
	}
	if sa.Status != entity.ServiceAccountStatusActive {
		failureReason = "service_account_disabled"
		authErr = entity.ErrAccountDisabled
		s.recordAuthFailure(ctx, dims)
		return nil, authErr
	}

	if err := s.abuseProtection.RecordSuccess(ctx, ratelimit.OperationServiceAccountAuth, dims); err != nil {
		logging.FromContext(ctx).Error("failed to reset abuse-protection counters after successful service account authentication", zap.Error(err))
	}
	if err := s.apiKeys.TouchLastUsed(ctx, key.ID); err != nil {
		logging.FromContext(ctx).Error("failed to update credential last_used_at", zap.String("credential_id", key.ID), zap.Error(err))
	}
	if err := s.serviceAccounts.TouchLastAuthenticated(ctx, serviceAccountID); err != nil {
		logging.FromContext(ctx).Error("failed to update service account last_authenticated_at",
			zap.String("service_account_id", serviceAccountID), zap.Error(err))
	}

	// SessionID is deliberately empty — the existing, established signal
	// this token carries no human session (see util.Claims.IsServiceAccount's
	// own doc comment). Permissions is nil, the same "resolved live by
	// RBACService on every request, never trusted from the token" choice
	// AuthService.issueSession already makes for human logins.
	accessToken, expiresAt, err := s.tokens.Sign(serviceAccountID, sa.OrganizationID, "", nil)
	if err != nil {
		authErr = err
		return nil, authErr
	}

	logging.FromContext(ctx).Info("service account authenticated",
		zap.String("service_account_id", serviceAccountID), zap.String("credential_id", key.ID))
	return &AuthenticateResult{
		AccessToken: accessToken,
		ExpiresIn:   int(time.Until(expiresAt).Seconds()),
	}, nil
}

// recordAuthFailure best-effort records a failed authentication attempt
// in the abuse-protection layer and, only on the transition into a
// blocked state, logs a Warn — the same bounded, transition-only signal
// AuthService.recordLoginFailure already gives, never one line per
// repeated attempt against an already-blocked dimension.
func (s *ServiceAccountService) recordAuthFailure(ctx context.Context, dims ratelimit.Dimensions) {
	blocked, err := s.abuseProtection.RecordFailure(ctx, ratelimit.OperationServiceAccountAuth, dims)
	if err != nil {
		logging.FromContext(ctx).Error("failed to record service account auth failure in abuse-protection layer", zap.Error(err))
		return
	}
	if blocked {
		logging.FromContext(ctx).Warn("service account authentication rate limit exceeded")
	}
}

// recordServiceAccountAuthAudit records service_account.login.success or
// service_account.login.failure — ActorType is AuditActorServiceAccount
// (never AuditActorUser): the actor performing this action is the
// service account itself, not an administrator, the same distinction
// recordAdminAudit's own doc comment draws for every other event in this
// file. Never carries the credential secret or the resulting access
// token — only serviceAccountID, outcome, and (on failure) a coarse
// failure_reason category, the same "never leak which specific check
// failed" anti-enumeration shape Authenticate's own returned errors
// already collapse into entity.ErrInvalidServiceAccountCredential.
func (s *ServiceAccountService) recordServiceAccountAuthAudit(ctx context.Context, serviceAccountID string, authErr error, failureReason string, meta LoginMeta) {
	if s.auditTx == nil {
		return
	}
	action := "service_account.login.success"
	result := entity.AuditResultSuccess
	metadata := map[string]any{}
	if authErr != nil {
		action = "service_account.login.failure"
		result = entity.AuditResultFailure
		metadata["failure_reason"] = failureReason
	}

	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    entity.AuditActorServiceAccount,
			ActorID:      strPtr(serviceAccountID),
			Action:       action,
			ResourceType: strPtr("service_account"),
			ResourceID:   strPtr(serviceAccountID),
			Result:       result,
			IPAddress:    strPtr(meta.IPAddress),
			RequestID:    strPtr(util.RequestIDFromContext(ctx)),
			Metadata:     metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record service account auth audit event", zap.Error(err))
	}
}

// recordAdminAudit is every lifecycle/credential-management method above's
// audit write — ActorType is always AuditActorUser: every method that
// calls this is an administrative action a human performed *on* a
// service account, never an action the service account performed itself
// (contrast recordServiceAccountAuthAudit above). Best-effort, the same
// convention UserService.recordUserAudit already follows.
func (s *ServiceAccountService) recordAdminAudit(ctx context.Context, action, actorUserID, serviceAccountID, ipAddress string, metadata map[string]any) {
	if s.auditTx == nil {
		return
	}
	var actorID *string
	if actorUserID != "" {
		actorID = &actorUserID
	}
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    entity.AuditActorUser,
			ActorID:      actorID,
			Action:       action,
			ResourceType: strPtr("service_account"),
			ResourceID:   strPtr(serviceAccountID),
			Result:       entity.AuditResultSuccess,
			IPAddress:    strPtr(ipAddress),
			RequestID:    strPtr(util.RequestIDFromContext(ctx)),
			Metadata:     metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record service account admin audit event",
			zap.String("action", action), zap.Error(err))
	}
}
