package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type refreshTokenRepository struct{ db *sql.DB }

func NewRefreshTokenRepository(db *sql.DB) repository.RefreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

const refreshTokenColumns = `id, session_id, user_id, token_hash, family_id, parent_token_id,
	issued_at, expires_at, revoked_at, revoked_reason, replaced_by_token_id`

func scanRefreshToken(row interface{ Scan(dest ...any) error }) (*entity.RefreshToken, error) {
	var t entity.RefreshToken
	var parentTokenID, revokedReason, replacedByTokenID sql.NullString
	var revokedAt sql.NullTime
	err := row.Scan(&t.ID, &t.SessionID, &t.UserID, &t.TokenHash, &t.FamilyID, &parentTokenID,
		&t.IssuedAt, &t.ExpiresAt, &revokedAt, &revokedReason, &replacedByTokenID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.ParentTokenID = nullString(parentTokenID)
	t.ReplacedByTokenID = nullString(replacedByTokenID)
	t.RevokedAt = nullTime(revokedAt)
	if revokedReason.Valid {
		reason := entity.RevocationReason(revokedReason.String)
		t.RevokedReason = &reason
	}
	return &t, nil
}

func (r *refreshTokenRepository) Create(ctx context.Context, t *entity.RefreshToken) error {
	const q = `
		INSERT INTO refresh_tokens (session_id, user_id, token_hash, family_id, parent_token_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, issued_at`
	err := r.db.QueryRowContext(ctx, q, t.SessionID, t.UserID, t.TokenHash, t.FamilyID,
		toNullString(t.ParentTokenID), t.ExpiresAt,
	).Scan(&t.ID, &t.IssuedAt)
	return translateError(err)
}

func (r *refreshTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	return scanRefreshToken(r.db.QueryRowContext(ctx, `SELECT `+refreshTokenColumns+` FROM refresh_tokens WHERE token_hash = $1`, tokenHash))
}

// Rotate marks `current` revoked-with-replacement and inserts `next` inside
// one transaction: a crash between the two statements must never leave a
// token that is both "still valid" and "already replaced" — that ambiguity
// is exactly what reuse detection depends on being impossible.
func (r *refreshTokenRepository) Rotate(ctx context.Context, current *entity.RefreshToken, next *entity.RefreshToken) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after a successful Commit

	err = tx.QueryRowContext(ctx, `
		INSERT INTO refresh_tokens (session_id, user_id, token_hash, family_id, parent_token_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, issued_at`,
		next.SessionID, next.UserID, next.TokenHash, next.FamilyID, toNullString(next.ParentTokenID), next.ExpiresAt,
	).Scan(&next.ID, &next.IssuedAt)
	if err != nil {
		return translateError(err)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = now(), revoked_reason = $1, replaced_by_token_id = $2
		WHERE id = $3 AND revoked_at IS NULL`,
		entity.RevocationRotation, next.ID, current.ID)
	if err := checkRowsAffected(res, err); err != nil {
		return err
	}

	return tx.Commit()
}

func (r *refreshTokenRepository) RevokeFamily(ctx context.Context, familyID string, reason entity.RevocationReason) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = $1 WHERE family_id = $2 AND revoked_at IS NULL`,
		reason, familyID)
	return err
}
