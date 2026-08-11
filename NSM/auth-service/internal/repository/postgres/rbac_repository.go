package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type roleRepository struct {
	db dbtx
}

// NewRoleRepository returns a repository.RoleRepository backed by
// PostgreSQL — the first implementation of this interface (previously
// declared but unused; see service.RBACService and the role-management
// HTTP handlers, its first real callers).
func NewRoleRepository(db dbtx) repository.RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) Create(ctx context.Context, role *entity.Role) error {
	const q = `
		INSERT INTO roles (organization_id, name, description, is_system_role)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, q, toNullString(role.OrganizationID), role.Name, toNullString(role.Description), role.IsSystemRole).
		Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
	return translateError(err)
}

const roleColumns = `id, organization_id, name, description, is_system_role, created_at, updated_at`

func scanRole(row interface{ Scan(dest ...any) error }) (*entity.Role, error) {
	var role entity.Role
	var orgID, description sql.NullString
	err := row.Scan(&role.ID, &orgID, &role.Name, &description, &role.IsSystemRole, &role.CreatedAt, &role.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	role.OrganizationID = nullString(orgID)
	role.Description = nullString(description)
	return &role, nil
}

func (r *roleRepository) GetByID(ctx context.Context, id string) (*entity.Role, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+roleColumns+` FROM roles WHERE id = $1`, id)
	return scanRole(row)
}

// List returns organizationID's own roles plus every system-wide role
// (organization_id IS NULL) — matching this method's own doc comment in
// internal/repository/rbac.go.
func (r *roleRepository) List(ctx context.Context, organizationID string, cursor *string, limit int) ([]*entity.Role, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+roleColumns+` FROM roles WHERE organization_id = $1 OR organization_id IS NULL ORDER BY is_system_role DESC, name ASC LIMIT $2`,
		organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*entity.Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *roleRepository) Update(ctx context.Context, role *entity.Role) error {
	const q = `
		UPDATE roles SET name = $1, description = $2, updated_at = now()
		WHERE id = $3 AND is_system_role = false
		RETURNING updated_at`
	err := r.db.QueryRowContext(ctx, q, role.Name, toNullString(role.Description), role.ID).Scan(&role.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.ErrNotFound
	}
	return err
}

func (r *roleRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM roles WHERE id = $1 AND is_system_role = false`, id)
	return checkRowsAffected(res, err)
}

func (r *roleRepository) AddPermission(ctx context.Context, rp *entity.RolePermission) error {
	const q = `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		RETURNING granted_at`
	err := r.db.QueryRowContext(ctx, q, rp.RoleID, rp.PermissionID).Scan(&rp.GrantedAt)
	return translateError(err)
}

func (r *roleRepository) RemovePermission(ctx context.Context, roleID, permissionID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`, roleID, permissionID)
	return checkRowsAffected(res, err)
}

func (r *roleRepository) ListPermissions(ctx context.Context, roleID string) ([]*entity.Permission, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT p.id, p.resource, p.action, p.description FROM permissions p
		 JOIN role_permissions rp ON rp.permission_id = p.id
		 WHERE rp.role_id = $1 ORDER BY p.resource, p.action`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissions(rows)
}

type permissionRepository struct {
	db dbtx
}

// NewPermissionRepository returns a repository.PermissionRepository
// backed by PostgreSQL.
func NewPermissionRepository(db dbtx) repository.PermissionRepository {
	return &permissionRepository{db: db}
}

func (r *permissionRepository) GetByID(ctx context.Context, id string) (*entity.Permission, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, resource, action, description FROM permissions WHERE id = $1`, id)
	var p entity.Permission
	var description sql.NullString
	err := row.Scan(&p.ID, &p.Resource, &p.Action, &description)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Description = nullString(description)
	return &p, nil
}

func (r *permissionRepository) List(ctx context.Context, resource *string, cursor *string, limit int) ([]*entity.Permission, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	query := `SELECT id, resource, action, description FROM permissions`
	var args []any
	if resource != nil {
		args = append(args, *resource)
		query += ` WHERE resource = $1`
	}
	args = append(args, limit)
	query += ` ORDER BY resource, action` + placeholder(" LIMIT $", len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissions(rows)
}

func scanPermissions(rows *sql.Rows) ([]*entity.Permission, error) {
	var out []*entity.Permission
	for rows.Next() {
		var p entity.Permission
		var description sql.NullString
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &description); err != nil {
			return nil, err
		}
		p.Description = nullString(description)
		out = append(out, &p)
	}
	return out, rows.Err()
}

type rbacRepository struct {
	db dbtx
}

// NewRBACRepository returns a repository.RBACRepository backed by
// PostgreSQL.
func NewRBACRepository(db dbtx) repository.RBACRepository {
	return &rbacRepository{db: db}
}

// UserHasPermission joins user_roles -> role_permissions -> permissions,
// filtering to non-expired grants (mirrors userRepository.ListRoles'
// identical "expires_at IS NULL OR expires_at > now()" clause — JIT
// grants must stop counting the moment they expire, not just stop
// appearing in a listing).
func (r *rbacRepository) UserHasPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_roles ur
			JOIN role_permissions rp ON rp.role_id = ur.role_id
			JOIN permissions p ON p.id = rp.permission_id
			WHERE ur.user_id = $1
			  AND p.resource = $2 AND p.action = $3
			  AND (ur.expires_at IS NULL OR ur.expires_at > now())
		)`, userID, resource, action).Scan(&exists)
	return exists, err
}

func (r *rbacRepository) UserPermissions(ctx context.Context, userID string) ([]*entity.Permission, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT p.id, p.resource, p.action, p.description
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1
		  AND (ur.expires_at IS NULL OR ur.expires_at > now())
		ORDER BY p.resource, p.action`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPermissions(rows)
}

func (r *rbacRepository) CountUsersWithRole(ctx context.Context, roleID string) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT count(DISTINCT user_id) FROM user_roles WHERE role_id = $1 AND (expires_at IS NULL OR expires_at > now())`,
		roleID).Scan(&n)
	return n, err
}
