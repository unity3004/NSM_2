package entity

import "time"

// Role is a named, reusable bundle of permissions. OrganizationID is nil for
// built-in system roles (shared across every tenant); non-nil for a
// tenant-defined custom role.
type Role struct {
	ID             string
	OrganizationID *string
	Name           string
	Description    *string
	IsSystemRole   bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Permission is an atomic, system-defined capability: a Resource ("secret",
// "user") paired with an Action ("read", "write"). Permissions are global,
// not tenant-scoped, and — deliberately — have no repository Create/Delete
// methods; see internal/repository/rbac_repository.go.
type Permission struct {
	ID          string
	Resource    string
	Action      string
	Description *string
}

// Name reproduces the DB's generated `resource || ':' || action` column so
// callers never have to compute it twice.
func (p *Permission) Name() string {
	return p.Resource + ":" + p.Action
}

// RolePermission is the role<->permission junction row (role_permissions).
type RolePermission struct {
	RoleID       string
	PermissionID string
	GrantedAt    time.Time
}
