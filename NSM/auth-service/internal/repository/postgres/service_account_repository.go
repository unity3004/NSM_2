package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type serviceAccountRepository struct {
	db dbtx
}

// NewServiceAccountRepository returns a repository.ServiceAccountRepository
// backed by PostgreSQL — the first implementation of this interface,
// previously declared (Sprint 2/3 scaffolding) but unused, the same
// "schema and interface existed, nothing built on them yet" state
// roleRepository's own doc comment already documented for RBAC before
// Sprint 2.7.
func NewServiceAccountRepository(db dbtx) repository.ServiceAccountRepository {
	return &serviceAccountRepository{db: db}
}

const serviceAccountColumns = `id, organization_id, name, description, status, created_by, created_at, updated_at, last_authenticated_at`

func scanServiceAccount(row interface{ Scan(dest ...any) error }) (*entity.ServiceAccount, error) {
	var sa entity.ServiceAccount
	var description, createdBy sql.NullString
	var lastAuthenticatedAt sql.NullTime
	err := row.Scan(&sa.ID, &sa.OrganizationID, &sa.Name, &description, &sa.Status,
		&createdBy, &sa.CreatedAt, &sa.UpdatedAt, &lastAuthenticatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sa.Description = nullString(description)
	sa.CreatedBy = nullString(createdBy)
	sa.LastAuthenticatedAt = nullTime(lastAuthenticatedAt)
	return &sa, nil
}

func (r *serviceAccountRepository) Create(ctx context.Context, sa *entity.ServiceAccount) error {
	const q = `
		INSERT INTO service_accounts (organization_id, name, description, status, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, q, sa.OrganizationID, sa.Name, toNullString(sa.Description), sa.Status, toNullString(sa.CreatedBy)).
		Scan(&sa.ID, &sa.CreatedAt, &sa.UpdatedAt)
	return translateError(err)
}

func (r *serviceAccountRepository) GetByID(ctx context.Context, id string) (*entity.ServiceAccount, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+serviceAccountColumns+` FROM service_accounts WHERE id = $1`, id)
	return scanServiceAccount(row)
}

func (r *serviceAccountRepository) List(ctx context.Context, organizationID string, cursor *string, limit int) ([]*entity.ServiceAccount, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+serviceAccountColumns+` FROM service_accounts WHERE organization_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
		organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*entity.ServiceAccount
	for rows.Next() {
		sa, err := scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

// Update persists Name/Description/Status only — CreatedBy and
// LastAuthenticatedAt are never caller-settable through this method (see
// TouchLastAuthenticated for the latter), the same "some columns have
// their own dedicated write path" rule userRepository.Update already
// follows for users.locked_until/failed_login_attempts.
func (r *serviceAccountRepository) Update(ctx context.Context, sa *entity.ServiceAccount) error {
	const q = `
		UPDATE service_accounts SET name = $1, description = $2, status = $3, updated_at = now()
		WHERE id = $4
		RETURNING updated_at`
	err := r.db.QueryRowContext(ctx, q, sa.Name, toNullString(sa.Description), sa.Status, sa.ID).Scan(&sa.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.ErrNotFound
	}
	return translateError(err)
}

func (r *serviceAccountRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM service_accounts WHERE id = $1`, id)
	return checkRowsAffected(res, err)
}

func (r *serviceAccountRepository) TouchLastAuthenticated(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE service_accounts SET last_authenticated_at = now() WHERE id = $1`, id)
	return err
}

func (r *serviceAccountRepository) GrantRole(ctx context.Context, grant *entity.ServiceAccountRole) error {
	const q = `
		INSERT INTO service_account_roles (service_account_id, role_id, assigned_by)
		VALUES ($1, $2, $3)
		RETURNING assigned_at`
	err := r.db.QueryRowContext(ctx, q, grant.ServiceAccountID, grant.RoleID, toNullString(grant.AssignedBy)).
		Scan(&grant.AssignedAt)
	return translateError(err)
}

func (r *serviceAccountRepository) RevokeRole(ctx context.Context, serviceAccountID, roleID string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM service_account_roles WHERE service_account_id = $1 AND role_id = $2`, serviceAccountID, roleID)
	return checkRowsAffected(res, err)
}

func (r *serviceAccountRepository) ListRoles(ctx context.Context, serviceAccountID string) ([]*entity.ServiceAccountRole, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT service_account_id, role_id, assigned_by, assigned_at FROM service_account_roles WHERE service_account_id = $1`,
		serviceAccountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []*entity.ServiceAccountRole
	for rows.Next() {
		var g entity.ServiceAccountRole
		var assignedBy sql.NullString
		if err := rows.Scan(&g.ServiceAccountID, &g.RoleID, &assignedBy, &g.AssignedAt); err != nil {
			return nil, err
		}
		g.AssignedBy = nullString(assignedBy)
		grants = append(grants, &g)
	}
	return grants, rows.Err()
}
