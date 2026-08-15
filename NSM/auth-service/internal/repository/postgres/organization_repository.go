package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type organizationRepository struct {
	db dbtx
}

// NewOrganizationRepository returns a repository.OrganizationRepository
// backed by PostgreSQL — the first implementation of this interface
// (previously declared but unused; see service.BootstrapService, its
// first real caller).
func NewOrganizationRepository(db dbtx) repository.OrganizationRepository {
	return &organizationRepository{db: db}
}

func (r *organizationRepository) Create(ctx context.Context, o *entity.Organization) error {
	const q = `
		INSERT INTO organizations (name, slug, status)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, q, o.Name, o.Slug, o.Status).
		Scan(&o.ID, &o.CreatedAt, &o.UpdatedAt)
	return translateError(err)
}

func (r *organizationRepository) scanOrganization(row interface{ Scan(dest ...any) error }) (*entity.Organization, error) {
	var o entity.Organization
	err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.Status, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &o, nil
}

const organizationColumns = `id, name, slug, status, created_at, updated_at`

func (r *organizationRepository) GetByID(ctx context.Context, id string) (*entity.Organization, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE id = $1`, id)
	return r.scanOrganization(row)
}

func (r *organizationRepository) GetBySlug(ctx context.Context, slug string) (*entity.Organization, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+organizationColumns+` FROM organizations WHERE slug = $1`, slug)
	return r.scanOrganization(row)
}

func (r *organizationRepository) Update(ctx context.Context, o *entity.Organization) error {
	const q = `
		UPDATE organizations SET name = $1, status = $2, updated_at = now()
		WHERE id = $3
		RETURNING updated_at`
	err := r.db.QueryRowContext(ctx, q, o.Name, o.Status, o.ID).Scan(&o.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.ErrNotFound
	}
	return err
}
