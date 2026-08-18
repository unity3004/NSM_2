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

// defaultReEncryptBatchSize is used whenever a caller passes
// batchSize <= 0 — the objective's own "the batch size should be
// configurable where appropriate" requirement, without forcing every
// caller to pick a number just to get sane behavior.
const defaultReEncryptBatchSize = 100

// ErrReEncryptFromActiveKey means ReEncryptBatch/ReEncryptAll was asked
// to migrate records away from the deployment's own currently-ACTIVE
// key — refused, because "identify records encrypted with non-active
// keys" (this engine's whole purpose) can never legitimately include the
// key EncryptionService.Encrypt is choosing for every brand-new write
// right now. Migrating those away would just have them migrated right
// back the moment anything re-reads/re-writes them, and — more
// seriously — doing so while fromKeyID is still ACTIVE would compete
// with every concurrent Encrypt call that assumes it still is.
var ErrReEncryptFromActiveKey = errors.New("service: cannot re-encrypt away from the currently active key")

// ReEncryptRecordFailure describes one record ReEncryptBatch could not
// migrate — safe to log or return to an operator: it names the secret
// version's identity and a short failure category, never plaintext,
// ciphertext, or key material.
type ReEncryptRecordFailure struct {
	SecretID  string
	Version   int
	VersionID string
	Category  string
}

// ReEncryptBatchResult summarizes one ReEncryptBatch call.
type ReEncryptBatchResult struct {
	// Considered is how many rows this batch actually looked at — 0
	// means there was nothing left under fromKeyID at the moment this
	// batch ran, the signal ReEncryptAll uses to stop looping.
	Considered int
	Migrated   int
	// Skipped counts a row ReEncryptVersion reported as already changed
	// since this batch's own read (migrated by an earlier or concurrent
	// run) — never a failure, and never retried within this same batch.
	Skipped  int
	Failures []ReEncryptRecordFailure
}

// ReEncryptSummary is ReEncryptAll's own aggregate result across every
// batch it ran.
type ReEncryptSummary struct {
	BatchesRun int
	Migrated   int
	Skipped    int
	Failures   []ReEncryptRecordFailure
}

// ReEncryptionService safely migrates secret_versions rows off an old,
// non-active encryption key onto the deployment's current active key —
// the KEY-001 ciphertext -> decrypt -> plaintext -> encrypt -> KEY-002
// ciphertext flow. It performs no cryptography of its own: encryption and
// decryption are delegated entirely to the existing
// secrets.EncryptionService (the identical instance service.SecretService
// itself already uses), so there remains exactly one AES-256-GCM
// implementation in this codebase to audit, never a second one built for
// this purpose. This service's own job is orchestration only — finding
// the right rows, in bounded batches, and persisting the result safely —
// never touching plaintext beyond the one decrypt/encrypt round trip per
// record, and never returning it to any caller (see reencryptOne's own
// doc comment).
//
// What this phase deliberately does not do: retire the old key (see
// service.KeyRotationService.RetireKey, a separate, manually-triggered
// operation this service never calls), schedule or automate itself, or
// expose an HTTP surface — see this task's own explicit scope.
type ReEncryptionService struct {
	encryption *secrets.EncryptionService
	keyManager *secrets.KeyManager
	secretRepo repository.SecretRepository
	auditTx    AuditTxFunc
}

// NewReEncryptionService constructs a ReEncryptionService. auditTx may be
// nil, the same allowance every other AuditTxFunc dependency in this
// codebase makes — every operation still succeeds, it just doesn't get an
// audit trail entry.
func NewReEncryptionService(encryption *secrets.EncryptionService, keyManager *secrets.KeyManager, secretRepo repository.SecretRepository, auditTx AuditTxFunc) *ReEncryptionService {
	return &ReEncryptionService{encryption: encryption, keyManager: keyManager, secretRepo: secretRepo, auditTx: auditTx}
}

// ReEncryptBatch migrates up to batchSize secret_versions rows currently
// under fromKeyID onto the deployment's current active key, one record at
// a time: decrypt under fromKeyID, encrypt under whichever key is active
// right now (secrets.EncryptionService.Encrypt always chooses it —
// ReEncryptBatch never names a target key explicitly), then persist via
// SecretRepository.ReEncryptVersion's own compare-and-swap
// (WHERE key_id = fromKeyID) — see that method's own doc comment for the
// idempotency/concurrency guarantee this relies on entirely, without any
// locking of its own.
//
// batchSize <= 0 uses defaultReEncryptBatchSize. A record that fails to
// decrypt, fails to encrypt, or fails to persist is recorded in the
// result's Failures and skipped — its row is never touched (FAILURE
// SAFETY) — and the batch continues with the next record rather than
// aborting the whole batch. A record ReEncryptVersion reports as
// not-updated (already migrated by a concurrent or earlier run since this
// batch's own read) counts as Skipped, never a failure.
//
// Returns ErrReEncryptFromActiveKey, touching nothing, if fromKeyID is
// currently ACTIVE.
func (s *ReEncryptionService) ReEncryptBatch(ctx context.Context, actorUserID, fromKeyID string, batchSize int, ipAddress string) (ReEncryptBatchResult, error) {
	if actorUserID == "" {
		return ReEncryptBatchResult{}, entity.ErrForbidden
	}
	if batchSize <= 0 {
		batchSize = defaultReEncryptBatchSize
	}

	active, err := s.keyManager.ActiveMetadata(ctx)
	if err != nil {
		return ReEncryptBatchResult{}, fmt.Errorf("service: resolving the active key: %w", err)
	}
	if fromKeyID == active.KeyID {
		return ReEncryptBatchResult{}, ErrReEncryptFromActiveKey
	}

	versions, err := s.secretRepo.ListVersionsByKeyID(ctx, fromKeyID, batchSize)
	if err != nil {
		return ReEncryptBatchResult{}, fmt.Errorf("service: listing versions under key %q: %w", fromKeyID, err)
	}

	result := ReEncryptBatchResult{Considered: len(versions)}
	for _, v := range versions {
		migrated, skipped, failure := s.reencryptOne(ctx, v, fromKeyID)
		switch {
		case migrated:
			result.Migrated++
		case skipped:
			result.Skipped++
		default:
			result.Failures = append(result.Failures, failure)
			s.recordFailureAudit(ctx, actorUserID, fromKeyID, active.KeyID, failure, ipAddress)
		}
	}
	return result, nil
}

// ReEncryptAll repeatedly calls ReEncryptBatch until a batch considers
// zero records (nothing left under fromKeyID) or maxBatches batches have
// run, whichever comes first. maxBatches <= 0 means no bound — run until
// nothing is left; every individual batch stays bounded by batchSize
// regardless, so this never loads more than one batch's worth of rows
// into memory at a time even when run unbounded. maxBatches > 0 is a
// deliberate safety cap for an operator who wants to make and verify
// partial progress before continuing — this method itself is still
// something an operator (or a future admin surface — not built this
// phase) triggers explicitly, never a scheduled or automatic process.
//
// Writes key.reencryption.started before the first batch and
// key.reencryption.completed after the loop ends successfully (with a
// summary in its metadata: batches run, migrated, skipped, failed
// counts — never any record's plaintext, ciphertext, or key material) —
// the high-level audit trail this operation's own significance warrants,
// distinct from the per-record key.reencryption.record_failed events
// each ReEncryptBatch call already writes for its own failures.
func (s *ReEncryptionService) ReEncryptAll(ctx context.Context, actorUserID, fromKeyID string, batchSize, maxBatches int, ipAddress string) (ReEncryptSummary, error) {
	if actorUserID == "" {
		return ReEncryptSummary{}, entity.ErrForbidden
	}

	s.recordLifecycleAudit(ctx, "key.reencryption.started", actorUserID, fromKeyID, ipAddress, nil)

	var summary ReEncryptSummary
	for maxBatches <= 0 || summary.BatchesRun < maxBatches {
		result, err := s.ReEncryptBatch(ctx, actorUserID, fromKeyID, batchSize, ipAddress)
		if err != nil {
			s.recordLifecycleAudit(ctx, "key.reencryption.failed", actorUserID, fromKeyID, ipAddress,
				map[string]any{"error": reencryptFailureCategory(err)})
			return summary, err
		}
		summary.BatchesRun++
		summary.Migrated += result.Migrated
		summary.Skipped += result.Skipped
		summary.Failures = append(summary.Failures, result.Failures...)
		if result.Considered == 0 {
			break
		}
	}

	s.recordLifecycleAudit(ctx, "key.reencryption.completed", actorUserID, fromKeyID, ipAddress, map[string]any{
		"batches_run": summary.BatchesRun,
		"migrated":    summary.Migrated,
		"skipped":     summary.Skipped,
		"failed":      len(summary.Failures),
	})
	return summary, nil
}

// reencryptOne performs the decrypt -> encrypt -> persist round trip for
// exactly one row. plaintext never leaves this function — it is never
// returned, never logged, and best-effort zeroed the moment it is no
// longer needed, mirroring secrets.EncryptionService's own "plaintext
// never retained beyond the call" discipline one layer up (see that
// type's own doc comment). A failure at any of the three steps leaves the
// row completely untouched: Decrypt/Encrypt failing never reaches
// ReEncryptVersion at all, and ReEncryptVersion's own failure (a database
// error) means the UPDATE statement itself never committed.
func (s *ReEncryptionService) reencryptOne(ctx context.Context, v *entity.SecretVersion, fromKeyID string) (migrated, skipped bool, failure ReEncryptRecordFailure) {
	ec := secrets.EncryptContext{SecretID: v.SecretID, Version: v.Version}
	oldPayload := &secrets.EncryptedPayload{
		Ciphertext: v.Ciphertext,
		Nonce:      v.Nonce,
		AuthTag:    v.AuthTag,
		WrappedDEK: v.WrappedDEK,
		KeyID:      v.KeyID,
		Algorithm:  v.Algorithm,
	}

	plaintext, err := s.encryption.Decrypt(ctx, oldPayload, ec)
	if err != nil {
		return false, false, ReEncryptRecordFailure{SecretID: v.SecretID, Version: v.Version, VersionID: v.ID, Category: "decrypt_failed"}
	}
	defer zeroBytes(plaintext)

	newPayload, err := s.encryption.Encrypt(ctx, plaintext, ec)
	if err != nil {
		return false, false, ReEncryptRecordFailure{SecretID: v.SecretID, Version: v.Version, VersionID: v.ID, Category: "encrypt_failed"}
	}

	reencrypted, err := s.secretRepo.ReEncryptVersion(ctx, v.ID, repository.ReEncryptedEnvelope{
		Ciphertext: newPayload.Ciphertext,
		Nonce:      newPayload.Nonce,
		AuthTag:    newPayload.AuthTag,
		WrappedDEK: newPayload.WrappedDEK,
		KeyID:      newPayload.KeyID,
		Algorithm:  newPayload.Algorithm,
	}, fromKeyID)
	if err != nil {
		return false, false, ReEncryptRecordFailure{SecretID: v.SecretID, Version: v.Version, VersionID: v.ID, Category: "persist_failed"}
	}
	if !reencrypted {
		return false, true, ReEncryptRecordFailure{}
	}
	return true, false, ReEncryptRecordFailure{}
}

// zeroBytes is reencryptOne's own best-effort erasure of the plaintext it
// decrypts — the same defense-in-depth (not a guarantee — see
// secrets/encryption.go's own "MEMORY" doc comment discussion) every
// plaintext-handling call site in this codebase already applies. Declared
// here rather than reusing secrets' own unexported zero() because that
// package deliberately exports no plaintext-handling helpers at all (see
// its own package doc comment on why it has no dependency anything above
// EncryptionService could misuse).
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func reencryptFailureCategory(err error) string {
	switch {
	case errors.Is(err, ErrReEncryptFromActiveKey):
		return "from_active_key"
	case errors.Is(err, entity.ErrForbidden):
		return "forbidden"
	default:
		return "unknown"
	}
}

// recordLifecycleAudit is best-effort — it never surfaces a failure to
// the caller, the same convention KeyRotationService.recordKeyAudit
// already follows. OrganizationID is always nil: key/re-encryption
// management is platform-wide, not scoped to a tenant, the identical
// reasoning KeyRotationService's own recordKeyAudit documents.
func (s *ReEncryptionService) recordLifecycleAudit(ctx context.Context, action, actorUserID, keyID, ipAddress string, metadata map[string]any) {
	if s.auditTx == nil {
		return
	}
	actor := &actorUserID
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: nil,
			ActorType:      entity.AuditActorUser,
			ActorID:        actor,
			Action:         action,
			ResourceType:   strPtr("encryption_key"),
			ResourceID:     strPtr(keyID),
			Result:         entity.AuditResultSuccess,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record re-encryption audit event", zap.String("action", action), zap.Error(err))
	}
}

// recordFailureAudit records one record-level re-encryption failure —
// metadata is deliberately limited to identifiers and a short category
// string (see ReEncryptRecordFailure's own doc comment): never
// plaintext, ciphertext, or key material, satisfying the objective's own
// "for individual failures, record safe metadata only" requirement.
func (s *ReEncryptionService) recordFailureAudit(ctx context.Context, actorUserID, fromKeyID, toKeyID string, failure ReEncryptRecordFailure, ipAddress string) {
	if s.auditTx == nil {
		return
	}
	actor := &actorUserID
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: nil,
			ActorType:      entity.AuditActorUser,
			ActorID:        actor,
			Action:         "key.reencryption.record_failed",
			ResourceType:   strPtr("secret_version"),
			ResourceID:     strPtr(failure.VersionID),
			Result:         entity.AuditResultFailure,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata: map[string]any{
				"secret_id":   failure.SecretID,
				"version":     failure.Version,
				"from_key_id": fromKeyID,
				"to_key_id":   toKeyID,
				"category":    failure.Category,
			},
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record re-encryption failure audit event", zap.Error(err))
	}
}
