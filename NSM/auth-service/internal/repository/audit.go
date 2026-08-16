package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// LoginHistoryRepository is append-only: there is deliberately no Update or
// Delete method — see auth-service-database-schema.md §"login_history".
type LoginHistoryRepository interface {
	Record(ctx context.Context, e *entity.LoginHistoryEntry) error
	List(ctx context.Context, organizationID string, f LoginHistoryFilter) ([]*entity.LoginHistoryEntry, error)
}

type LoginHistoryFilter struct {
	UserID         *string
	Status         *entity.LoginStatus
	IPAddress      *string
	OccurredAfter  *string
	OccurredBefore *string
	Cursor         *string
	Limit          int
}

// AuditLogRepository is append-only for the same reason, plus a hash-chain
// invariant a mutation would break outright: Append must compute
// RecordHash from the previous row's hash, so there is no "Update" to offer.
type AuditLogRepository interface {
	Append(ctx context.Context, e *entity.AuditLogEntry) error
	GetByID(ctx context.Context, id string) (*entity.AuditLogEntry, error)
	List(ctx context.Context, organizationID string, f AuditLogFilter) ([]*entity.AuditLogEntry, error)
	// LatestHash returns the RecordHash of the most recent row for this
	// organization, so Append can chain the next one — nil/"" if this is
	// the first entry.
	LatestHash(ctx context.Context, organizationID string) (string, error)
}

type AuditLogFilter struct {
	ActorType      *entity.AuditActorType
	ActorID        *string
	ResourceType   *string
	ResourceID     *string
	Result         *entity.AuditResult
	OccurredAfter  *string
	OccurredBefore *string
	Cursor         *string
	Limit          int
}
