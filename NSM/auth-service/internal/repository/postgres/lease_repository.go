package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type leaseRepository struct {
	db dbtx
}

// NewLeaseRepository returns a repository.LeaseRepository backed by
// PostgreSQL.
func NewLeaseRepository(db dbtx) repository.LeaseRepository {
	return &leaseRepository{db: db}
}

const leaseColumns = `id, organization_id, lease_type, resource_path, owner_identity_type, owner_identity_id,
	status, renewable, ttl_seconds, max_ttl_seconds, created_at, expires_at, revoked_at, revoked_reason,
	provider_reference, metadata`

func scanLease(row interface{ Scan(dest ...any) error }) (*entity.Lease, error) {
	var l entity.Lease
	var revokedAt sql.NullTime
	var revokedReason, providerRef sql.NullString
	var ttlSeconds, maxTTLSeconds int
	var metadataJSON []byte
	err := row.Scan(&l.ID, &l.OrganizationID, &l.LeaseType, &l.ResourcePath, &l.OwnerIdentityType, &l.OwnerIdentityID,
		&l.Status, &l.Renewable, &ttlSeconds, &maxTTLSeconds, &l.CreatedAt, &l.ExpiresAt, &revokedAt, &revokedReason,
		&providerRef, &metadataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	l.TTL = time.Duration(ttlSeconds) * time.Second
	l.MaxTTL = time.Duration(maxTTLSeconds) * time.Second
	l.RevokedAt = nullTime(revokedAt)
	l.RevokedReason = nullString(revokedReason)
	l.ProviderRef = nullString(providerRef)
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &l.Metadata); err != nil {
			return nil, err
		}
	}
	return &l, nil
}

func (r *leaseRepository) Create(ctx context.Context, l *entity.Lease) error {
	metadataJSON, err := json.Marshal(l.Metadata)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO leases (organization_id, lease_type, resource_path, owner_identity_type, owner_identity_id,
			status, renewable, ttl_seconds, max_ttl_seconds, expires_at, provider_reference, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at`
	err = r.db.QueryRowContext(ctx, q,
		l.OrganizationID, l.LeaseType, l.ResourcePath, l.OwnerIdentityType, l.OwnerIdentityID,
		l.Status, l.Renewable, int(l.TTL.Seconds()), int(l.MaxTTL.Seconds()), l.ExpiresAt,
		toNullString(l.ProviderRef), metadataJSON,
	).Scan(&l.ID, &l.CreatedAt)
	return translateError(err)
}

func (r *leaseRepository) GetByID(ctx context.Context, id string) (*entity.Lease, error) {
	return scanLease(r.db.QueryRowContext(ctx, `SELECT `+leaseColumns+` FROM leases WHERE id = $1`, id))
}

func (r *leaseRepository) List(ctx context.Context, organizationID string, f repository.LeaseFilter) ([]*entity.Lease, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	query := `SELECT ` + leaseColumns + ` FROM leases WHERE organization_id = $1`
	args := []any{organizationID}
	if f.OwnerIdentityType != nil {
		args = append(args, *f.OwnerIdentityType)
		query += placeholder(" AND owner_identity_type = $", len(args))
	}
	if f.OwnerIdentityID != nil {
		args = append(args, *f.OwnerIdentityID)
		query += placeholder(" AND owner_identity_id = $", len(args))
	}
	if f.Status != nil {
		args = append(args, *f.Status)
		query += placeholder(" AND status = $", len(args))
	}
	args = append(args, limit)
	query += ` ORDER BY created_at DESC, id DESC` + placeholder(" LIMIT $", len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*entity.Lease
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Renew only ever touches a currently LeaseStatusActive row — a lease
// LeaseService has already independently re-verified is not expired
// (see that method's own doc comment) — so this WHERE clause is a second,
// database-level guarantee against renewing a lease a concurrent revoke
// or expiration-cleanup pass raced this call to transition out of
// LeaseStatusActive first.
func (r *leaseRepository) Renew(ctx context.Context, id string, newTTL time.Duration, newExpiresAt time.Time) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE leases SET ttl_seconds = $1, expires_at = $2 WHERE id = $3 AND status = 'active'`,
		int(newTTL.Seconds()), newExpiresAt, id)
	return checkRowsAffected(res, err)
}

func (r *leaseRepository) Revoke(ctx context.Context, id string, reason *string, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE leases SET status = 'revoked', revoked_at = $1, revoked_reason = $2 WHERE id = $3 AND status = 'active'`,
		at, toNullString(reason), id)
	if err != nil {
		return false, translateError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ExpireOverdue is the database-level half of expiration enforcement —
// see entity.Lease.IsExpired's own doc comment for why authorization
// itself never depends on this having run. RETURNING gives the caller
// (the cleanup worker) exactly the rows it transitioned, so it can audit
// precisely what happened rather than re-querying to find out.
func (r *leaseRepository) ExpireOverdue(ctx context.Context, at time.Time) ([]*entity.Lease, error) {
	rows, err := r.db.QueryContext(ctx,
		`UPDATE leases SET status = 'expired' WHERE status = 'active' AND expires_at <= $1 RETURNING `+leaseColumns,
		at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*entity.Lease
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
