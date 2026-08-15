package service

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

// RoleService is the read path for roles and permissions — GET /v1/roles,
// GET /v1/roles/{roleId}, GET /v1/permissions, and the role-name/
// permission lookups the user-detail endpoint needs to render "roles" and
// "permissions derived from roles" for a specific user. Role and
// permission *mutation* (creating a custom role, changing its permission
// grants) is deliberately out of scope for this sprint — every role this
// system has is platform-seeded (see migrations 000021/000023), and nothing
// here exposes a way to create or delete one; RoleRepository/PermissionRepository
// already have Create/Delete methods for when tenant-defined custom roles
// are actually built, but this service never calls them.
type RoleService struct {
	roles       repository.RoleRepository
	permissions repository.PermissionRepository
	rbac        repository.RBACRepository
}

func NewRoleService(roles repository.RoleRepository, permissions repository.PermissionRepository, rbac repository.RBACRepository) *RoleService {
	return &RoleService{roles: roles, permissions: permissions, rbac: rbac}
}

func (s *RoleService) GetRole(ctx context.Context, id string) (*entity.Role, error) {
	return s.roles.GetByID(ctx, id)
}

// ListRoles returns organizationID's roles plus every system-wide role —
// see RoleRepository.List's own doc comment.
func (s *RoleService) ListRoles(ctx context.Context, organizationID string) ([]*entity.Role, error) {
	return s.roles.List(ctx, organizationID, nil, 100)
}

func (s *RoleService) ListRolePermissions(ctx context.Context, roleID string) ([]*entity.Permission, error) {
	return s.roles.ListPermissions(ctx, roleID)
}

func (s *RoleService) ListAllPermissions(ctx context.Context) ([]*entity.Permission, error) {
	return s.permissions.List(ctx, nil, nil, 200)
}

// CountUsersWithRole backs the Roles page's "number of users" column.
func (s *RoleService) CountUsersWithRole(ctx context.Context, roleID string) (int, error) {
	return s.rbac.CountUsersWithRole(ctx, roleID)
}
