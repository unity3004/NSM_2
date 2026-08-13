package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type apiKeyRepository struct {
	db dbtx
}

// NewAPIKeyRepository returns a repository.APIKeyRepository backed by
// PostgreSQL — the first implementation of an interface that, like
// ServiceAccountRepository's, has existed since this schema's original
// design (migrations 000013/000014) with nothing behind it (Sprint 5 Task
// 1). No method here ever selects key_hash back out for display — only
// GetByKeyHash reads it, and only to compare against a caller-supplied
// hash, never to return it — see entity.APIKey's own doc comment.
func NewAPIKeyRepository(db dbtx) repository.APIKeyRepository {
	return &apiKeyRepository{db: db}
}

const apiKeyColumns = `id, organization_id, owner_user_id, owner_service_account_id, name,
	key_prefix, key_hash, status, last_used_at, expires_at, created_at, revoked_at, revoked_reason`

func scanAPIKey(row interface{ Scan(dest ...any) error }) (*entity.APIKey, error) {
	var k entity.APIKey
	var ownerUserID, ownerServiceAccountID, revokedReason sql.NullString
	var lastUsedAt, expiresAt, revokedAt sql.NullTime
	err := row.Scan(&k.ID, &k.OrganizationID, &ownerUserID, &ownerServiceAccountID, &k.Name,
		&k.KeyPrefix, &k.KeyHash, &k.Status, &lastUsedAt, &expiresAt, &k.CreatedAt, &revokedAt, &revokedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	k.OwnerUserID = nullString(ownerUserID)
	k.OwnerServiceAccountID = nullString(ownerServiceAccountID)
	k.LastUsedAt = nullTime(lastUsedAt)
	k.ExpiresAt = nullTime(expiresAt)
	k.RevokedAt = nullTime(revokedAt)
	k.RevokedReason = nullString(revokedReason)
	return &k, nil
}

// Create rejects a key with both or neither owner set before it ever
// reaches the database — entity.APIKey.HasSingleOwner's own doc comment
// on why the Go check exists ahead of ck_api_keys_single_owner, not as a
// replacement for it.
func (r *apiKeyRepository) Create(ctx context.Context, k *entity.APIKey) error {
	if !k.HasSingleOwner() {
		return entity.ErrOwnerConflict
	}
	const q = `
		INSERT INTO api_keys (organization_id, owner_user_id, owner_service_account_id, name, key_prefix, key_hash, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at`
	err := r.db.QueryRowContext(ctx, q,
		k.OrganizationID, toNullString(k.OwnerUserID), toNullString(k.OwnerServiceAccountID),
		k.Name, k.KeyPrefix, k.KeyHash, k.Status, toNullTime(k.ExpiresAt),
	).Scan(&k.ID, &k.CreatedAt)
	return translateError(err)
}

func (r *apiKeyRepository) GetByID(ctx context.Context, id string) (*entity.APIKey, error) {
	return scanAPIKey(r.db.QueryRowContext(ctx, `SELECT `+apiKeyColumns+` FROM api_keys WHERE id = $1`, id))
}

// GetByKeyHash is machine authentication's one lookup query — key_hash
// carries a UNIQUE constraint (uq_api_keys_key_hash), so this is an exact,
// O(1)-indexed match, never a scan; see
// service.ServiceAccountService.Authenticate for the only caller.
func (r *apiKeyRepository) GetByKeyHash(ctx context.Context, keyHash string) (*entity.APIKey, error) {
	return scanAPIKey(r.db.QueryRowContext(ctx, `SELECT `+apiKeyColumns+` FROM api_keys WHERE key_hash = $1`, keyHash))
}

func (r *apiKeyRepository) List(ctx context.Context, organizationID string, f repository.ApiKeyFilter) ([]*entity.APIKey, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `SELECT ` + apiKeyColumns + ` FROM api_keys WHERE organization_id = $1`
	args := []any{organizationID}
	if f.OwnerUserID != nil {
		args = append(args, *f.OwnerUserID)
		query += ` AND owner_user_id = $` + strconv.Itoa(len(args))
	}
	if f.OwnerServiceAccountID != nil {
		args = append(args, *f.OwnerServiceAccountID)
		query += ` AND owner_service_account_id = $` + strconv.Itoa(len(args))
	}
	if f.Status != nil {
		args = append(args, *f.Status)
		query += ` AND status = $` + strconv.Itoa(len(args))
	}
	args = append(args, limit)
	query += ` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*entity.APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Revoke is idempotent-safe against a double-revoke racing itself (the
// WHERE clause only matches a key that is still active), reported as
// entity.ErrNotFound the same way checkRowsAffected already reports any
// other "matched zero rows" mutation — a caller that revokes an
// already-revoked key learns that rather than silently re-stamping
// revoked_at/revoked_reason with new values that would misrepresent when
// the key actually stopped being usable.
func (r *apiKeyRepository) Revoke(ctx context.Context, id string, reason *string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE api_keys SET status = 'revoked', revoked_at = now(), revoked_reason = $1
		 WHERE id = $2 AND status = 'active'`,
		toNullString(reason), id)
	return checkRowsAffected(res, err)
}

func (r *apiKeyRepository) TouchLastUsed(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
	return err
}

func (r *apiKeyRepository) AddPermission(ctx context.Context, p *entity.APIKeyPermission) error {
	const q = `INSERT INTO api_key_permissions (api_key_id, permission_id) VALUES ($1, $2)`
	_, err := r.db.ExecContext(ctx, q, p.APIKeyID, p.PermissionID)
	return translateError(err)
}

func (r *apiKeyRepository) RemovePermission(ctx context.Context, apiKeyID, permissionID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM api_key_permissions WHERE api_key_id = $1 AND permission_id = $2`, apiKeyID, permissionID)
	return checkRowsAffected(res, err)
}

func (r *apiKeyRepository) ListPermissions(ctx context.Context, apiKeyID string) ([]*entity.Permission, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT p.id, p.resource, p.action, p.description FROM permissions p
		 JOIN api_key_permissions akp ON akp.permission_id = p.id
		 WHERE akp.api_key_id = $1 ORDER BY p.resource, p.action`, apiKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissions(rows)
}
