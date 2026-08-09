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
