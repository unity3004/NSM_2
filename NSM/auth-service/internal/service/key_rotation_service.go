package service

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/secrets"
	"github.com/acme/auth-service/internal/util"
)

// KeyRotationService is the operational front door for
// internal/secrets.KeyManager — the one place key lifecycle transitions
// get an actor, an audit trail, and (for retirement) a real check against
// secret_versions before they're allowed to happen. KeyManager itself
// cannot perform that check (internal/secrets has no repository
// dependency — see that package's own doc comment) or write an audit
// entry (same reasoning; it has no logging dependency either), so this
// service exists specifically to supply both, the same way SecretService
// supplies RBAC and audit logging on top of EncryptionService.
//
// This phase adds no REST endpoints for any of this — see this sprint's
// own explicit scope ("Do NOT implement... automatic mass re-encryption")
// and NSM/key-management-architecture.md's operational-responsibilities
// section for how these methods are meant to be invoked (an operator
// tool/admin CLI, a later phase) and by whom.
type KeyRotationService struct {
	keyManager *secrets.KeyManager
	secretRepo repository.SecretRepository
	auditTx    AuditTxFunc
}

// NewKeyRotationService constructs a KeyRotationService. auditTx may be
// nil, the same allowance every other AuditTx dependency in this codebase
// makes (see SecretService.NewSecretService) — every operation still
// succeeds, it just doesn't get an audit trail entry.
func NewKeyRotationService(keyManager *secrets.KeyManager, secretRepo repository.SecretRepository, auditTx AuditTxFunc) *KeyRotationService {
	return &KeyRotationService{keyManager: keyManager, secretRepo: secretRepo, auditTx: auditTx}
}

// EnsureBootstrapped registers the key provider's current key as this
// deployment's first ACTIVE key, if this is genuinely the first time
// anything has asked KeyManager for a key. Intended to be called once at
// process startup (cmd/server/main.go), so a misconfiguration fails the
// process immediately rather than surfacing later as a confusing
// encryption failure on the first real request, and so the resulting
// key.created/key.activated audit events are attributable to "system
// startup" specifically rather than folded into whichever request happens
// to trigger bootstrap lazily. Safe to call on every startup: a no-op,
// with no audit events written, once bootstrap has already happened once.
func (s *KeyRotationService) EnsureBootstrapped(ctx context.Context) (secrets.KeyMetadata, error) {
	meta, didBootstrap, err := s.keyManager.Bootstrap(ctx)
	if err != nil {
		return secrets.KeyMetadata{}, err
	}
	if didBootstrap {
		s.recordKeyAudit(ctx, "key.created", nil, meta.KeyID, entity.AuditResultSuccess, "", nil)
		s.recordKeyAudit(ctx, "key.activated", nil, meta.KeyID, entity.AuditResultSuccess, "", nil)
	}
	return meta, nil
}

// CurrentKey returns the active key's metadata — never key material.
func (s *KeyRotationService) CurrentKey(ctx context.Context) (secrets.KeyMetadata, error) {
	return s.keyManager.ActiveMetadata(ctx)
}

// ListKeys returns every known key's metadata, most-recently-created
// first.
func (s *KeyRotationService) ListKeys(ctx context.Context) ([]secrets.KeyMetadata, error) {
	return s.keyManager.ListKeys(ctx)
}

// RotateKey makes newKeyID the current key — see secrets.KeyManager.Rotate
// for the mechanics and safeguards. actorUserID identifies who triggered
// this (never "" — rotation is always a deliberate, attributed action,
// unlike bootstrap); ipAddress is carried into the audit trail the same
// way every other service in this codebase records it.
//
// Writes key.rotation_started before attempting the rotation and
// key.rotation_completed only after it succeeds — a failed rotation (an
// unavailable new key, for instance) leaves a rotation_started/failure
// pair in audit_logs with no matching completed event, an honest record
// of "an operator tried to rotate to key X and it did not happen," rather
// than silence.
func (s *KeyRotationService) RotateKey(ctx context.Context, actorUserID, newKeyID, ipAddress string) (secrets.KeyMetadata, error) {
	if actorUserID == "" {
		return secrets.KeyMetadata{}, entity.ErrForbidden
	}
	actor := &actorUserID
	s.recordKeyAudit(ctx, "key.rotation_started", actor, newKeyID, entity.AuditResultSuccess, ipAddress, nil)

	meta, err := s.keyManager.Rotate(ctx, newKeyID)
	if err != nil {
		s.recordKeyAudit(ctx, "key.rotation_started", actor, newKeyID, entity.AuditResultFailure, ipAddress, map[string]any{"error": rotationFailureCategory(err)})
		return secrets.KeyMetadata{}, err
	}

	s.recordKeyAudit(ctx, "key.rotation_completed", actor, newKeyID, entity.AuditResultSuccess, ipAddress, nil)
	s.recordKeyAudit(ctx, "key.activated", actor, newKeyID, entity.AuditResultSuccess, ipAddress, nil)
	return meta, nil
}

// RetireKey moves keyID from KeyStateRetiring to KeyStateRetired — but
// only after confirming, via a real query against secret_versions, that
// nothing still references it. This is the objective's ROTATION SAFETY
// requirement in full: "a key may only be retired after determining that
// no remaining encrypted data requires it," implemented as an actual
// count query, not an assumption. Refuses with an error naming the
// reference count (never any key material) if the count is nonzero.
func (s *KeyRotationService) RetireKey(ctx context.Context, actorUserID, keyID, ipAddress string) error {
	if actorUserID == "" {
		return entity.ErrForbidden
	}
	count, err := s.secretRepo.CountVersionsByKeyID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("service: checking whether key %q is still referenced: %w", keyID, err)
	}
	if count > 0 {
		return fmt.Errorf("service: key %q is still referenced by %d secret version(s) and cannot be retired", keyID, count)
	}

	actor := &actorUserID
	if err := s.keyManager.Retire(ctx, keyID); err != nil {
		s.recordKeyAudit(ctx, "key.retired", actor, keyID, entity.AuditResultFailure, ipAddress, nil)
		return err
	}
	s.recordKeyAudit(ctx, "key.retired", actor, keyID, entity.AuditResultSuccess, ipAddress, nil)
	return nil
}

// DisableKey moves keyID to KeyStateDisabled — see KeyStateDisabled's own
// doc comment for what this means operationally (emergency revocation,
// not routine rotation) and why there is no corresponding "enable"
// method. reason is recorded in the audit trail's metadata (a short
// operator-supplied string, e.g. "suspected compromise") — never key
// material, and this method does not validate or interpret it beyond
// that.
func (s *KeyRotationService) DisableKey(ctx context.Context, actorUserID, keyID, reason, ipAddress string) error {
	if actorUserID == "" {
		return entity.ErrForbidden
	}
	actor := &actorUserID
	if err := s.keyManager.DisableKey(ctx, keyID); err != nil {
		s.recordKeyAudit(ctx, "key.disabled", actor, keyID, entity.AuditResultFailure, ipAddress, nil)
		return err
	}
	s.recordKeyAudit(ctx, "key.disabled", actor, keyID, entity.AuditResultSuccess, ipAddress, map[string]any{"reason": reason})
	return nil
}

// rotationFailureCategory turns a Rotate() error into a short, safe
// category string for audit metadata — never the raw error text, which
// for ErrKeyUnavailable wraps whatever the underlying KeyProvider (a
// future KMS client) said, text this codebase makes no guarantee never
// mentions configuration details that shouldn't sit in audit_logs
// indefinitely.
func rotationFailureCategory(err error) string {
	switch {
	case errors.Is(err, secrets.ErrKeyAlreadyExists):
		return "key_already_exists"
	case errors.Is(err, secrets.ErrKeyUnavailable):
		return "key_unavailable"
	default:
		return "unknown"
	}
}

// recordKeyAudit is best-effort — it never surfaces a failure to the
// caller, the same convention SecretService.recordSecretAudit and
// UserService.recordUserAudit already follow (see either's own doc
// comment). OrganizationID is always nil: key management is platform-wide,
// not scoped to a tenant (see migrations/000026's own doc comment).
// actorUserID nil means AuditActorSystem (process startup / bootstrap,
// not a human) rather than AuditActorUser — the same distinction
// entity.AuditActorType already exists to make. metadata never carries
// key material — every call site above passes only key identifiers,
// short category strings, and operator-supplied reason text.
func (s *KeyRotationService) recordKeyAudit(ctx context.Context, action string, actorUserID *string, keyID string, result entity.AuditResult, ipAddress string, metadata map[string]any) {
	if s.auditTx == nil {
		return
	}
	actorType := entity.AuditActorSystem
	if actorUserID != nil {
		actorType = entity.AuditActorUser
	}
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: nil,
			ActorType:      actorType,
			ActorID:        actorUserID,
			Action:         action,
			ResourceType:   strPtr("encryption_key"),
			ResourceID:     strPtr(keyID),
			Result:         result,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record key management audit event",
			zap.String("action", action), zap.String("key_id", keyID), zap.Error(err))
	}
}
