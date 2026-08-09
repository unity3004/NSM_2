package postgres

import (
	"context"
	"database/sql"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type loginHistoryRepository struct{ db *sql.DB }

func NewLoginHistoryRepository(db *sql.DB) repository.LoginHistoryRepository {
	return &loginHistoryRepository{db: db}
}

// Record inserts one attempt row. There is no corresponding Update: every
// login attempt — success or failure, known identity or not — is written
// exactly once, before the HTTP response is returned, so the audit trail
// can't be bypassed by an error path. See entity.LoginHistoryEntry.
func (r *loginHistoryRepository) Record(ctx context.Context, e *entity.LoginHistoryEntry) error {
	const q = `
		INSERT INTO login_history (organization_id, user_id, attempted_identifier, status, auth_method, ip_address, session_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, occurred_at`
	err := r.db.QueryRowContext(ctx, q,
		toNullString(e.OrganizationID), toNullString(e.UserID), toNullString(e.AttemptedIdentifier),
		e.Status, e.AuthMethod, toNullString(e.IPAddress), toNullString(e.SessionID),
	).Scan(&e.ID, &e.OccurredAt)
	return err
}

func (r *loginHistoryRepository) List(ctx context.Context, organizationID string, f repository.LoginHistoryFilter) ([]*entity.LoginHistoryEntry, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	query := `SELECT id, organization_id, user_id, attempted_identifier, status, auth_method,
		ip_address, session_id, occurred_at FROM login_history WHERE organization_id = $1`
	args := []any{organizationID}
	if f.UserID != nil {
		args = append(args, *f.UserID)
		query += placeholder(" AND user_id = $", len(args))
	}
	if f.Status != nil {
		args = append(args, *f.Status)
		query += placeholder(" AND status = $", len(args))
	}
	if f.IPAddress != nil {
		args = append(args, *f.IPAddress)
		query += placeholder(" AND ip_address = $", len(args))
	}
	args = append(args, limit)
	query += " ORDER BY occurred_at DESC" + placeholder(" LIMIT $", len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*entity.LoginHistoryEntry
	for rows.Next() {
		var e entity.LoginHistoryEntry
		var orgID, userID, attemptedID, ip, sessionID sql.NullString
		if err := rows.Scan(&e.ID, &orgID, &userID, &attemptedID, &e.Status, &e.AuthMethod, &ip, &sessionID, &e.OccurredAt); err != nil {
			return nil, err
		}
		e.OrganizationID = nullString(orgID)
		e.UserID = nullString(userID)
		e.AttemptedIdentifier = nullString(attemptedID)
		e.IPAddress = nullString(ip)
		e.SessionID = nullString(sessionID)
		out = append(out, &e)
	}
	return out, rows.Err()
}
