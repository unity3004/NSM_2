package repository

import (
	"context"
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// LeaseFilter narrows LeaseRepository.List — every field is optional
// (zero value means "don't filter on this").
type LeaseFilter struct {
	OwnerIdentityType *entity.LeaseOwnerType
	OwnerIdentityID   *string
	Status            *entity.LeaseStatus
	Limit             int
}

// LeaseRepository persists entity.Lease — metadata and lifecycle state
// only; see that type's own doc comment for why it never carries
// credential material to persist in the first place.
type LeaseRepository interface {
	Create(ctx context.Context, l *entity.Lease) error
	GetByID(ctx context.Context, id string) (*entity.Lease, error)
	List(ctx context.Context, organizationID string, f LeaseFilter) ([]*entity.Lease, error)
	// Renew updates TTL/ExpiresAt in place — the same "advance the window,
	// don't replace the row" shape entity.Lease.TTL's own doc comment
	// describes. Fails with entity.ErrNotFound if id doesn't name a
	// currently LeaseStatusActive row (the caller — LeaseService.Renew —
	// has already made the renewability decision; this method only
	// persists it).
	Renew(ctx context.Context, id string, newTTL time.Duration, newExpiresAt time.Time) error
	// Revoke transitions id to LeaseStatusRevoked — a no-op-safe write
	// (WHERE status = 'active') so a race between two concurrent revokes
	// of the same lease can never double-fire whatever side effect the
	// caller attaches to "this call actually revoked it" (see
	// entity.APIKeyRepository.Revoke's identical convention).
	// alreadyRevoked reports whether this specific call is what performed
	// the transition (false means the lease was already revoked/expired
	// and this call was a no-op) — the same "which caller actually
	// transitioned the state" signal RecordFailure's own blocked bool
	// gives ratelimit callers, used here to keep revocation audit entries
	// bounded to one per lease.
	Revoke(ctx context.Context, id string, reason *string, at time.Time) (transitioned bool, err error)
	// ExpireOverdue transitions every currently LeaseStatusActive row
	// whose expires_at is at or before at to LeaseStatusExpired — the
	// database-level half of expiration enforcement (see
	// entity.Lease.IsExpired's own doc comment on why authorization never
	// depends on this having run yet). Returns the rows it actually
	// transitioned, so a caller (the cleanup worker) can audit exactly
	// what it did.
	ExpireOverdue(ctx context.Context, at time.Time) ([]*entity.Lease, error)
}
