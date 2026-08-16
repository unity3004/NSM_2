package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type sessionRepository struct{ db *sql.DB }

func NewSessionRepository(db *sql.DB) repository.SessionRepository {
	return &sessionRepository{db: db}
}

const sessionColumns = `id, user_id, session_token_hash, ip_address, user_agent,
	device_fingerprint, created_at, last_active_at, expires_at, revoked_at, revoked_reason`

func (r *sessionRepository) scan(row interface{ Scan(dest ...any) error }) (*entity.Session, error) {
	var s entity.Session
	var ip, ua, fp, revokedReason sql.NullString
	var revokedAt sql.NullTime
	err := row.Scan(&s.ID, &s.UserID, &s.SessionTokenHash, &ip, &ua, &fp,
		&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &revokedAt, &revokedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.IPAddress = nullString(ip)
	s.UserAgent = nullString(ua)
	s.DeviceFingerprint = nullString(fp)
	s.RevokedAt = nullTime(revokedAt)
	if revokedReason.Valid {
		reason := entity.RevocationReason(revokedReason.String)
		s.RevokedReason = &reason
	}
	return &s, nil
}

func (r *sessionRepository) Create(ctx context.Context, s *entity.Session) error {
	const q = `
		INSERT INTO sessions (user_id, session_token_hash, ip_address, user_agent, device_fingerprint, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, last_active_at`
	err := r.db.QueryRowContext(ctx, q, s.UserID, s.SessionTokenHash, toNullString(s.IPAddress),
		toNullString(s.UserAgent), toNullString(s.DeviceFingerprint), s.ExpiresAt,
	).Scan(&s.ID, &s.CreatedAt, &s.LastActiveAt)
	return translateError(err)
}

func (r *sessionRepository) GetByID(ctx context.Context, id string) (*entity.Session, error) {
	return r.scan(r.db.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id))
}

func (r *sessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*entity.Session, error) {
	return r.scan(r.db.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE session_token_hash = $1`, tokenHash))
}

func (r *sessionRepository) ListActiveByUser(ctx context.Context, userID string) ([]*entity.Session, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY last_active_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*entity.Session
	for rows.Next() {
		s, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *sessionRepository) Touch(ctx context.Context, id string, lastActiveAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET last_active_at = $1 WHERE id = $2`, lastActiveAt, id)
	return err
}

func (r *sessionRepository) Revoke(ctx context.Context, id string, reason entity.RevocationReason) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = now(), revoked_reason = $1 WHERE id = $2 AND revoked_at IS NULL`,
		reason, id)
	return checkRowsAffected(res, err)
}

func (r *sessionRepository) RevokeAllForUser(ctx context.Context, userID string, reason entity.RevocationReason) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = now(), revoked_reason = $1 WHERE user_id = $2 AND revoked_at IS NULL`,
		reason, userID)
	return err
}
