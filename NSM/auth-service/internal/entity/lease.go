package entity

import "time"

// LeaseStatus mirrors the lease_status Postgres enum.
type LeaseStatus string

const (
	LeaseStatusActive  LeaseStatus = "active"
	LeaseStatusRevoked LeaseStatus = "revoked"
	LeaseStatusExpired LeaseStatus = "expired"
)

// LeaseOwnerType mirrors the lease_owner_type Postgres enum — the same
// two-value identity-type split util.Claims.IsServiceAccount already
// carries for authentication, reused here so a lease's ownership is
// expressed the same unambiguous way ("this ID means nothing without also
// knowing which table it names") every other identity-typed field in this
// codebase already requires (see RBACRepository.ServiceAccountHasPermission's
// own doc comment on why a bare ID string is never enough on its own).
type LeaseOwnerType string

const (
	LeaseOwnerUser           LeaseOwnerType = "user"
	LeaseOwnerServiceAccount LeaseOwnerType = "service_account"
)

// Lease is a temporary grant tracking a dynamically-issued credential's
// lifecycle — never the credential itself. See
// internal/service/lease_service.go's own package doc comment for the
// "static secret vs. dynamic lease, two separate models" distinction this
// type exists to keep real.
type Lease struct {
	ID                string
	OrganizationID    string
	LeaseType         string
	ResourcePath      string
	OwnerIdentityType LeaseOwnerType
	OwnerIdentityID   string
	Status            LeaseStatus
	Renewable         bool
	// TTL is the currently-effective remaining-lifetime window — advances
	// on every renewal to the newly granted window; never itself a
	// timestamp (ExpiresAt is the timestamp; TTL is "how long," ExpiresAt
	// is "until when").
	TTL time.Duration
	// MaxTTL is a fixed ceiling snapshotted from configuration at
	// creation time — neither TTL nor any renewal's newly requested TTL
	// may ever push ExpiresAt past CreatedAt+MaxTTL. See
	// LeaseService.Renew's own doc comment.
	MaxTTL        time.Duration
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	ProviderRef   *string
	Metadata      map[string]any
}

// IsExpired reports whether now is at or past ExpiresAt — the
// authorization-time check every lease-consuming code path must run
// itself, never trusting Status alone: a background cleanup worker
// transitions Status to LeaseStatusExpired eventually, but this method is
// what makes an expired lease unusable *immediately*, the instant
// current_time >= expires_at, regardless of whether that worker has run
// yet (the objective's own explicit requirement).
func (l *Lease) IsExpired(now time.Time) bool {
	return !now.Before(l.ExpiresAt)
}

// IsUsable reports whether this lease may currently be relied upon for
// anything — active status and not yet expired. Both LeaseService and any
// future dynamic-secret consumer should gate on this, never on Status
// alone, for the identical "authorization must check expiration itself"
// reason IsExpired's own doc comment gives.
func (l *Lease) IsUsable(now time.Time) bool {
	return l.Status == LeaseStatusActive && !l.IsExpired(now)
}
