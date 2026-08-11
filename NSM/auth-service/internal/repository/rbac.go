package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// RoleRepository persists entity.Role and its permission grants.
type RoleRepository interface {
	Create(ctx context.Context, r *entity.Role) error
	GetByID(ctx context.Context, id string) (*entity.Role, error)
	// List returns tenant-defined roles for organizationID plus every
	// system-wide role (Role.OrganizationID == nil) — see the OpenAPI
	// description on GET /roles.
	List(ctx context.Context, organizationID string, cursor *string, limit int) ([]*entity.Role, error)
	Update(ctx context.Context, r *entity.Role) error
	Delete(ctx context.Context, id string) error

	AddPermission(ctx context.Context, rp *entity.RolePermission) error
	RemovePermission(ctx context.Context, roleID, permissionID string) error
	ListPermissions(ctx context.Context, roleID string) ([]*entity.Permission, error)
}

// PermissionRepository is read-only by design — permissions are
// platform-seeded, not tenant-created. See auth-service-api-design.md §6.
type PermissionRepository interface {
	GetByID(ctx context.Context, id string) (*entity.Permission, error)
	List(ctx context.Context, resource *string, cursor *string, limit int) ([]*entity.Permission, error)
}

// RBACRepository answers the questions authorization enforcement and the
// admin UI actually ask, each of which spans user_roles + role_permissions
// + permissions in one query — deliberately separate from
// RoleRepository/PermissionRepository (CRUD on one entity at a time),
// the same way AuditLogRepository is its own interface rather than a
// method bolted onto UserRepository.
type RBACRepository interface {
	// UserHasPermission is the one query every authorization check this
	// service performs boils down to: does userID currently hold, via
	// any non-expired direct role grant, a permission matching
	// resource:action. Real-time against the database on every call,
	// deliberately never cached or read from a JWT claim — see
	// service.RBACService's own doc comment for why.
	UserHasPermission(ctx context.Context, userID, resource, action string) (bool, error)
	// UserPermissions returns every permission userID currently holds,
	// union across all their role grants — backs "permissions derived
	// from roles" on the user detail page.
	UserPermissions(ctx context.Context, userID string) ([]*entity.Permission, error)
	// CountUsersWithRole backs the Roles page's "number of users" column.
	CountUsersWithRole(ctx context.Context, roleID string) (int, error)
}
