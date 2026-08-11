package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// PlatformBootstrapRepository backs the one-time first-administrator
// bootstrap flow (service.BootstrapService). Every method here is meant to
// be called against a transaction-scoped instance (see database.WithTx),
// the same convention UserService.Register's RegistrationTxFunc already
// establishes — LockForBootstrap in particular only serializes concurrent
// callers when it runs inside a real transaction; against a bare *sql.DB
// the row lock would be released before the caller could do anything with
// it.
type PlatformBootstrapRepository interface {
	// LockForBootstrap takes a row lock (SELECT ... FOR UPDATE) on the
	// platform_bootstrap singleton row and returns its current status. A
	// second concurrent call, in a different transaction, blocks here
	// until the first transaction commits or rolls back — this is the one
	// mechanism that makes "exactly one administrator, ever" true under
	// concurrent requests, not the uniqueness of any column.
	LockForBootstrap(ctx context.Context) (entity.PlatformBootstrapStatus, error)
	// MarkInitializing records the transition out of "uninitialized" —
	// see entity.PlatformInitializing's doc comment on why this is real
	// but not independently observable by a non-locking status read.
	MarkInitializing(ctx context.Context) error
	// MarkInitialized records the successful, terminal transition and who
	// performed it.
	MarkInitialized(ctx context.Context, adminUserID string) error
	// Status is the non-locking read GET /v1/platform/status uses — it
	// must never block behind a bootstrap attempt in progress.
	Status(ctx context.Context) (entity.PlatformBootstrapStatus, error)
	// FirstOrganizationID returns the oldest existing organization, if
	// any. Bootstrap attaches the new administrator to it when a
	// deployment has already pre-provisioned an organization by some
	// other means; otherwise bootstrap creates a default one itself. This
	// lives here, not on OrganizationRepository, because "find any
	// organization at all" is a bootstrap-specific question — every other
	// caller in this codebase already knows which organization it means.
	FirstOrganizationID(ctx context.Context) (id string, found bool, err error)
}
