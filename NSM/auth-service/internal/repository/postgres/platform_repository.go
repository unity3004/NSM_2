package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type platformBootstrapRepository struct {
	db dbtx
}

// NewPlatformBootstrapRepository returns a repository.PlatformBootstrapRepository
// backed by PostgreSQL. Like NewAuditLogRepository, LockForBootstrap only
// does its job (serializing concurrent callers) when db is a transaction —
// see that method's own doc comment.
func NewPlatformBootstrapRepository(db dbtx) repository.PlatformBootstrapRepository {
	return &platformBootstrapRepository{db: db}
}

func (r *platformBootstrapRepository) LockForBootstrap(ctx context.Context) (entity.PlatformBootstrapStatus, error) {
	var status entity.PlatformBootstrapStatus
	err := r.db.QueryRowContext(ctx, `SELECT status FROM platform_bootstrap WHERE id = 1 FOR UPDATE`).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		// The migration that creates this table always inserts its one
		// row — reaching here means the table exists but the seed insert
		// was somehow skipped, a deployment/migration bug, not a client
		// error. Treated as "uninitialized" would be actively wrong (it
		// would let bootstrap proceed against a table that can't record
		// the result), so this is reported as a genuine error instead.
		return "", errors.New("postgres: platform_bootstrap has no row — migration 000020 did not seed it")
	}
	return status, err
}

func (r *platformBootstrapRepository) MarkInitializing(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `UPDATE platform_bootstrap SET status = 'initializing' WHERE id = 1`)
	return err
}

func (r *platformBootstrapRepository) MarkInitialized(ctx context.Context, adminUserID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE platform_bootstrap SET status = 'initialized', initialized_by = $1, initialized_at = now() WHERE id = 1`,
		adminUserID)
	return err
}

func (r *platformBootstrapRepository) Status(ctx context.Context) (entity.PlatformBootstrapStatus, error) {
	var status entity.PlatformBootstrapStatus
	err := r.db.QueryRowContext(ctx, `SELECT status FROM platform_bootstrap WHERE id = 1`).Scan(&status)
	return status, err
}

func (r *platformBootstrapRepository) FirstOrganizationID(ctx context.Context) (string, bool, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `SELECT id FROM organizations ORDER BY created_at ASC, id ASC LIMIT 1`).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return id, true, nil
}
