package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/service"
)

type roleHandler struct {
	svc *service.RoleService
}

// list implements GET /v1/roles — every role visible to the caller's
// organization (tenant-defined plus system-wide; see RoleRepository.List),
// each annotated with its live user count and permission list so the
// Roles page never has to make N+1 requests to render what the
// specification's own mockup shows in one screen.
func (h *roleHandler) list(w http.ResponseWriter, r *http.Request) {
	orgID := organizationIDFromRequest(r)
	roles, err := h.svc.ListRoles(r.Context(), orgID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}

	out := make([]dto.RoleWithPermissionsResponse, 0, len(roles))
	for _, role := range roles {
		perms, err := h.svc.ListRolePermissions(r.Context(), role.ID)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		userCount, err := h.svc.CountUsersWithRole(r.Context(), role.ID)
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		out = append(out, dto.RoleWithPermissionsResponse{
			RoleResponse: dto.RoleResponse{
				ID:             role.ID,
				OrganizationID: role.OrganizationID,
				Name:           role.Name,
				Description:    role.Description,
				IsSystemRole:   role.IsSystemRole,
				CreatedAt:      role.CreatedAt,
				UpdatedAt:      role.UpdatedAt,
			},
			UserCount:   userCount,
			Permissions: permissionResponses(perms),
		})
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.RoleWithPermissionsResponse `json:"data"`
	}{Data: out})
}

// get implements GET /v1/roles/{roleId}.
func (h *roleHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("roleId")
	role, err := h.svc.GetRole(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	perms, err := h.svc.ListRolePermissions(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	userCount, err := h.svc.CountUsersWithRole(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.RoleWithPermissionsResponse{
		RoleResponse: dto.RoleResponse{
			ID:             role.ID,
			OrganizationID: role.OrganizationID,
			Name:           role.Name,
			Description:    role.Description,
			IsSystemRole:   role.IsSystemRole,
			CreatedAt:      role.CreatedAt,
			UpdatedAt:      role.UpdatedAt,
		},
		UserCount:   userCount,
		Permissions: permissionResponses(perms),
	})
}

// listPermissions implements GET /v1/permissions — the full, flat
// platform-seeded catalog (see migrations 000021/000022), never
// tenant-scoped: PermissionRepository is read-only by design.
func (h *roleHandler) listPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.svc.ListAllPermissions(r.Context())
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.PermissionResponse `json:"data"`
	}{Data: permissionResponses(perms)})
}

func permissionResponses(perms []*entity.Permission) []dto.PermissionResponse {
	out := make([]dto.PermissionResponse, 0, len(perms))
	for _, p := range perms {
		out = append(out, dto.PermissionResponse{
			ID:          p.ID,
			Resource:    p.Resource,
			Action:      p.Action,
			Name:        p.Resource + ":" + p.Action,
			Description: p.Description,
		})
	}
	return out
}
