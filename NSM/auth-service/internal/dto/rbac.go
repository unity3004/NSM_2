package dto

import "time"

// RoleCreateRequest matches components.schemas.RoleCreate.
type RoleCreateRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

func (r RoleCreateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Name) == 0 || len(r.Name) > 100 {
		errs.Add("name", "is required and must be at most 100 characters")
	}
	return errs.Err()
}

// RoleResponse matches components.schemas.Role.
type RoleResponse struct {
	ID             string    `json:"id"`
	OrganizationID *string   `json:"organization_id,omitempty"`
	Name           string    `json:"name"`
	Description    *string   `json:"description,omitempty"`
	IsSystemRole   bool      `json:"is_system_role"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PermissionResponse matches components.schemas.Permission.
type PermissionResponse struct {
	ID          string  `json:"id"`
	Resource    string  `json:"resource"`
	Action      string  `json:"action"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// RoleWithPermissionsResponse is GET /v1/roles and GET /v1/roles/{roleId}'s
// body — RoleResponse plus its live permission list and current user
// count, so the Roles page renders in one request per the specification's
// own mockup ("Role / Description / Number of users / Permissions" in one
// screen), never N+1 follow-up calls per role.
type RoleWithPermissionsResponse struct {
	RoleResponse
	UserCount   int                   `json:"user_count"`
	Permissions []PermissionResponse `json:"permissions"`
}

// RoleGrantCreateRequest matches components.schemas.RoleGrantCreate — the
// shared shape behind POST /users/{id}/roles, POST /groups/{id}/roles, and
// POST /service-accounts/{id}/roles. ExpiresAt is only meaningful on the
// user variant (JIT access); the service layer ignores it for the other two.
type RoleGrantCreateRequest struct {
	RoleID    string     `json:"role_id"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (r RoleGrantCreateRequest) Validate() error {
	var errs ValidationErrors
	if r.RoleID == "" {
		errs.Add("role_id", "is required")
	}
	if r.ExpiresAt != nil && !r.ExpiresAt.After(time.Now()) {
		errs.Add("expires_at", "must be in the future")
	}
	return errs.Err()
}

// RoleGrantResponse matches components.schemas.RoleGrant.
type RoleGrantResponse struct {
	RoleID     string     `json:"role_id"`
	RoleName   string     `json:"role_name"`
	AssignedBy *string    `json:"assigned_by,omitempty"`
	AssignedAt time.Time  `json:"assigned_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// GroupCreateRequest matches components.schemas.GroupCreate.
type GroupCreateRequest struct {
	Name          string  `json:"name"`
	Description   *string `json:"description,omitempty"`
	ParentGroupID *string `json:"parent_group_id,omitempty"`
}

func (r GroupCreateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Name) == 0 || len(r.Name) > 150 {
		errs.Add("name", "is required and must be at most 150 characters")
	}
	return errs.Err()
}

// GroupResponse matches components.schemas.Group.
type GroupResponse struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ParentGroupID  *string   `json:"parent_group_id,omitempty"`
	Name           string    `json:"name"`
	Description    *string   `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
