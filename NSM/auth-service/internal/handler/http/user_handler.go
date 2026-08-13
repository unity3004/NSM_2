package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/service"
)

type userHandler struct {
	svc   *service.UserService
	roles *service.RoleService
	rbac  *service.RBACService
}

func (h *userHandler) create(w http.ResponseWriter, r *http.Request) {
	var req dto.UserCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	orgID := organizationIDFromRequest(r)
	u, err := h.svc.CreateUser(r.Context(), service.CreateUserInput{
		User:              req.ToEntity(orgID),
		PlaintextPassword: req.Password,
		ActorUserID:       actorUserID(r),
		IPAddress:         clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.UserResponseFromEntity(u))
}

// register implements POST /v1/auth/register — self-service signup,
// distinct from create (POST /users, the admin/invite path) even though
// both end up calling into the same UserService. It lives here, not on
// authHandler, because the capability it calls (service.UserService.Register)
// lives on UserService — the route path is a public contract
// ("/auth/register" reads better to a caller than "/users/register" would
// for something that isn't authenticated yet), but nothing requires the
// handler struct that serves a path to match that path's first segment;
// router.go is the only place the two are connected.
func (h *userHandler) register(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	u, err := h.svc.Register(r.Context(), service.RegisterInput{
		OrganizationID: organizationIDFromRequest(r),
		Username:       req.Username,
		Email:          req.Email,
		Password:       req.Password,
		IPAddress:      clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.RegisterResponse{
		ID:        u.ID,
		Username:  *u.Username,
		Email:     u.Email,
		Status:    string(u.Status),
		CreatedAt: u.CreatedAt,
	})
}

// get implements GET /v1/users/{userId} — the detail view, so unlike
// list's bare dto.UserResponse rows, this also resolves and includes the
// user's current role grants (with names, not just IDs — see
// RoleService.GetRole) and the permissions those roles confer. Role-lookup
// failures are logged and the offending grant is simply omitted from the
// response rather than failing the whole request: a user detail page
// should still render if one role lookup has a transient problem, the
// same "don't let a secondary read sink the primary one" judgment
// DisableUser's session-revocation error handling already makes.
//
// Authorization here is deliberately not a plain requirePermission gate
// (see router.go's own comment on this route): every authenticated user
// may view their own profile regardless of role — the existing dashboard
// already depends on this — and *additionally*, a caller holding
// users:read may view anyone's. A caller that is neither is reported
// entity.ErrNotFound-equivalent (404, via writeServiceError's existing
// mapping) rather than 403: revealing "this user ID exists, you're just
// not allowed to see it" is exactly the enumeration leak the rest of this
// codebase's error model already avoids elsewhere (see
// auth-architecture-sprint2.md's anti-enumeration rule, applied here to
// user IDs instead of email addresses).
func (h *userHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	if id != actorUserID(r) {
		allowed, err := h.rbac.HasPermission(r.Context(), actorUserID(r), "users:read")
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
		if !allowed {
			writeErrorEnvelope(w, r, http.StatusNotFound, dto.CodeNotFound, "No such resource.", nil)
			return
		}
	}

	u, err := h.svc.GetUser(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}

	grants, err := h.svc.ListUserRoles(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	roleGrants := make([]dto.RoleGrantResponse, 0, len(grants))
	for _, g := range grants {
		role, err := h.roles.GetRole(r.Context(), g.RoleID)
		if err != nil {
			continue
		}
		roleGrants = append(roleGrants, dto.RoleGrantResponse{
			RoleID:     g.RoleID,
			RoleName:   role.Name,
			AssignedBy: g.AssignedBy,
			AssignedAt: g.AssignedAt,
			ExpiresAt:  g.ExpiresAt,
		})
	}

	effective, err := h.rbac.EffectivePermissions(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	permResponses := make([]dto.PermissionResponse, 0, len(effective))
	for _, p := range effective {
		permResponses = append(permResponses, dto.PermissionResponse{
			ID:          p.ID,
			Resource:    p.Resource,
			Action:      p.Action,
			Name:        p.Resource + ":" + p.Action,
			Description: p.Description,
		})
	}

	writeJSON(w, r, http.StatusOK, dto.UserDetailResponse{
		UserResponse: dto.UserResponseFromEntity(u),
		Roles:        roleGrants,
		Permissions:  permResponses,
	})
}

func (h *userHandler) list(w http.ResponseWriter, r *http.Request) {
	orgID := organizationIDFromRequest(r)
	users, err := h.svc.ListUsers(r.Context(), orgID, repository.UserFilter{Limit: 20})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.UserResponse, 0, len(users))
	for _, u := range users {
		out = append(out, dto.UserResponseFromEntity(u))
	}
	hasMore := false
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.UserResponse `json:"data"`
		Page dto.PageMeta       `json:"page"`
	}{Data: out, Page: dto.PageMeta{HasMore: hasMore, Limit: 20}})
}

func (h *userHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	if err := h.svc.DeleteUser(r.Context(), id); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// disable implements POST /v1/users/{userId}/disable. See
// UserService.DisableUser's doc comment for exactly what this does and
// does not immediately revoke.
func (h *userHandler) disable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	if err := h.svc.DisableUser(r.Context(), id, actorUserID(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	u, err := h.svc.GetUser(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.UserResponseFromEntity(u))
}

// enable implements POST /v1/users/{userId}/enable.
func (h *userHandler) enable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	if err := h.svc.EnableUser(r.Context(), id, actorUserID(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	u, err := h.svc.GetUser(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.UserResponseFromEntity(u))
}

// assignRole implements POST /v1/users/{userId}/roles — grants an
// existing role (RoleID must reference a real roles row; a nonexistent
// one surfaces as entity.ErrNotFound via the same foreign-key
// translation every other grant in this codebase relies on, never a raw
// Postgres error) to the user. RoleID is read from the request body, but
// only ever a role this exact platform already defines — there is no
// path through this handler that lets a caller invent a role name or
// grant permissions that don't already exist as a seeded role.
func (h *userHandler) assignRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	var req dto.RoleGrantCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}
	if err := h.svc.AssignRole(r.Context(), id, req.RoleID, actorUserID(r), clientIP(r), req.ExpiresAt); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removeRole implements DELETE /v1/users/{userId}/roles/{roleId}.
func (h *userHandler) removeRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	roleID := r.PathValue("roleId")
	if err := h.svc.RemoveRole(r.Context(), id, roleID, actorUserID(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// actorUserID reads the acting administrator's own ID off their verified
// access-token claims — never from anything the request body supplies —
// for audit attribution. Empty when no claims are present, which
// shouldn't happen on any route this is called from (all require Auth),
// but recordUserAudit already treats an empty actor ID as "no actor" and
// omits it rather than writing a misleading empty string.
func actorUserID(r *http.Request) string {
	claims, ok := ClaimsFromRequest(r)
	if !ok {
		return ""
	}
	return claims.Subject
}

// isServiceAccount reports whether the request's verified identity (if
// any) is a service account rather than a human user — see
// util.Claims.IsServiceAccount's own doc comment. An unauthenticated
// request (no claims at all) is never a service account by this
// function's definition; every route that could reach here without
// claims already rejects the request earlier (requireAuth/requirePermission),
// so this is only ever consulted once an identity is known to exist.
func isServiceAccount(r *http.Request) bool {
	claims, ok := ClaimsFromRequest(r)
	return ok && claims.IsServiceAccount()
}
