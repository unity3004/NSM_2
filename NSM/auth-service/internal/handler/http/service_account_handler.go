package http

import (
	"errors"
	"net/http"
	"strings"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/service"
)

// serviceAccountHandler translates HTTP requests into
// service.ServiceAccountService calls and service results back into dto.*
// JSON — nothing else, the same narrow translation-only role every other
// handler in this package plays. Every admin route below (everything
// except token, see that method's own doc comment) reaches this handler
// only after requireAuth + requirePermission already ran (router.go) —
// this handler never checks a permission itself, the same UserService/
// userHandler precedent this type follows rather than SecretService's own
// internal-recheck one (see service.ServiceAccountService's own doc
// comment for why).
type serviceAccountHandler struct {
	svc   *service.ServiceAccountService
	roles *service.RoleService
	rbac  *service.RBACService
}

// create implements POST /v1/service-accounts.
func (h *serviceAccountHandler) create(w http.ResponseWriter, r *http.Request) {
	var req dto.ServiceAccountCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}
	sa, err := h.svc.CreateServiceAccount(r.Context(), service.CreateServiceAccountInput{
		OrganizationID: organizationIDFromRequest(r),
		Name:           req.Name,
		Description:    req.Description,
		ActorUserID:    actorUserID(r),
		IPAddress:      clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.ServiceAccountResponseFromEntity(sa))
}

// list implements GET /v1/service-accounts.
func (h *serviceAccountHandler) list(w http.ResponseWriter, r *http.Request) {
	accounts, err := h.svc.ListServiceAccounts(r.Context(), organizationIDFromRequest(r), nil, 20)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.ServiceAccountResponse, 0, len(accounts))
	for _, sa := range accounts {
		out = append(out, dto.ServiceAccountResponseFromEntity(sa))
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.ServiceAccountResponse `json:"data"`
		Page dto.PageMeta                 `json:"page"`
	}{Data: out, Page: dto.PageMeta{HasMore: false, Limit: 20}})
}

// get implements GET /v1/service-accounts/{serviceAccountId} — the detail
// view: metadata plus current role grants (with names, not just IDs) and
// the permissions those roles confer, the same shape userHandler.get
// already builds for a user's own detail page.
func (h *serviceAccountHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serviceAccountId")
	sa, err := h.svc.GetServiceAccount(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}

	grants, err := h.svc.ListRoles(r.Context(), id)
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
			RoleID: g.RoleID, RoleName: role.Name, AssignedBy: g.AssignedBy, AssignedAt: g.AssignedAt,
		})
	}

	effective, err := h.rbac.ServiceAccountEffectivePermissions(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	permResponses := make([]dto.PermissionResponse, 0, len(effective))
	for _, p := range effective {
		permResponses = append(permResponses, dto.PermissionResponse{
			ID: p.ID, Resource: p.Resource, Action: p.Action, Name: p.Resource + ":" + p.Action, Description: p.Description,
		})
	}

	writeJSON(w, r, http.StatusOK, dto.ServiceAccountDetailResponse{
		ServiceAccountResponse: dto.ServiceAccountResponseFromEntity(sa),
		Roles:                  roleGrants,
		Permissions:            permResponses,
	})
}

// update implements PATCH /v1/service-accounts/{serviceAccountId}. A
// status change routes through DisableServiceAccount/EnableServiceAccount
// — never a raw field write — so it carries the same credential-revocation
// side effect a dedicated disable endpoint would (see
// dto.ServiceAccountUpdateRequest's own doc comment).
func (h *serviceAccountHandler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serviceAccountId")
	var req dto.ServiceAccountUpdateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	if req.Status != nil {
		var err error
		switch entity.ServiceAccountStatus(*req.Status) {
		case entity.ServiceAccountStatusDisabled:
			err = h.svc.DisableServiceAccount(r.Context(), id, actorUserID(r), clientIP(r))
		case entity.ServiceAccountStatusActive:
			err = h.svc.EnableServiceAccount(r.Context(), id, actorUserID(r), clientIP(r))
		}
		if err != nil {
			writeServiceError(w, r, err)
			return
		}
	}

	sa, err := h.svc.UpdateServiceAccount(r.Context(), id, req.Name, req.Description, actorUserID(r), clientIP(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.ServiceAccountResponseFromEntity(sa))
}

// delete implements DELETE /v1/service-accounts/{serviceAccountId} — a
// hard delete; service_account_roles and every api_keys row it owns
// cascade-delete with it (migrations 000012/000013's own ON DELETE
// CASCADE), matching this route's own OpenAPI description.
func (h *serviceAccountHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serviceAccountId")
	if err := h.svc.DeleteServiceAccount(r.Context(), id, actorUserID(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listRoles implements GET /v1/service-accounts/{serviceAccountId}/roles
// — a bare array (dto.RoleGrantResponse), matching
// auth-service-openapi.yaml's own schema for this one endpoint (unlike
// most list endpoints in this codebase, it is not wrapped in a
// {data, page} envelope — service account role grants are never numerous
// enough to paginate).
func (h *serviceAccountHandler) listRoles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serviceAccountId")
	grants, err := h.svc.ListRoles(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.RoleGrantResponse, 0, len(grants))
	for _, g := range grants {
		role, err := h.roles.GetRole(r.Context(), g.RoleID)
		if err != nil {
			continue
		}
		out = append(out, dto.RoleGrantResponse{RoleID: g.RoleID, RoleName: role.Name, AssignedBy: g.AssignedBy, AssignedAt: g.AssignedAt})
	}
	writeJSON(w, r, http.StatusOK, out)
}

// assignRole implements POST /v1/service-accounts/{serviceAccountId}/roles
// — 201 with the created RoleGrant, matching auth-service-openapi.yaml's
// own response for this endpoint specifically (unlike
// userHandler.assignRole's 204, since the spec documents this one
// differently — see that operation's own responses block).
func (h *serviceAccountHandler) assignRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serviceAccountId")
	var req dto.RoleGrantCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}
	if err := h.svc.AssignRole(r.Context(), id, req.RoleID, actorUserID(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	role, err := h.roles.GetRole(r.Context(), req.RoleID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	actor := actorUserID(r)
	writeJSON(w, r, http.StatusCreated, dto.RoleGrantResponse{RoleID: req.RoleID, RoleName: role.Name, AssignedBy: &actor})
}

// removeRole implements DELETE /v1/service-accounts/{serviceAccountId}/roles/{roleId}.
func (h *serviceAccountHandler) removeRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serviceAccountId")
	roleID := r.PathValue("roleId")
	if err := h.svc.RemoveRole(r.Context(), id, roleID, actorUserID(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// token implements POST /v1/service-accounts/{serviceAccountId}/token —
// Client-credentials-style exchange (auth-service-openapi.yaml's own
// description). Deliberately NOT behind requireAuth/requirePermission:
// this route authenticates the request itself, via the X-Api-Key header
// (apiKeyAuth in the spec's own securitySchemes) rather than a bearer
// token — there is no existing identity yet for requireAuth to have
// verified. See router.go's own registration of this route for why it
// lives in the same "public: no bearer token exists yet" group as
// /auth/login.
func (h *serviceAccountHandler) token(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("serviceAccountId")

	secret := strings.TrimSpace(r.Header.Get("X-Api-Key"))
	if secret == "" {
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeUnauthenticated, "X-Api-Key header is required.", nil)
		return
	}

	// The body is optional (auth-service-openapi.yaml: `required: false`)
	// — an absent or empty body is not an error, only a malformed
	// non-empty one is (decodeJSON already treats "no body at all" as a
	// MALFORMED_REQUEST, which this endpoint must not: see that helper's
	// own doc comment for why it exists at all).
	if r.Body != nil && r.ContentLength != 0 {
		var req dto.ServiceAccountTokenRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := req.Validate(); err != nil {
			writeValidationError(w, r, err)
			return
		}
	}

	result, err := h.svc.Authenticate(r.Context(), id, secret, service.LoginMeta{IPAddress: clientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		writeServiceAccountAuthError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.ServiceTokenResponse{
		AccessToken: result.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   result.ExpiresIn,
	})
}

// writeServiceAccountAuthError maps Authenticate's errors to the split
// auth-service-openapi.yaml documents for this one endpoint specifically:
// 401 for a credential problem (missing/invalid/revoked/expired — the
// caller presented no usable proof of identity at all) vs. 403 for a
// disabled service account (the caller presented a genuinely valid
// credential; the identity it names is simply not allowed to authenticate
// right now) — a different split from writeServiceError's own default
// entity.ErrAccountDisabled case (403 with a different message) and
// entity.ErrInvalidServiceAccountCredential (which writeServiceError has
// no case for at all, so it would otherwise fall through to 500). Both
// messages stay generic — never which specific check failed — matching
// entity.ErrInvalidServiceAccountCredential's own anti-enumeration doc
// comment.
func writeServiceAccountAuthError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, entity.ErrInvalidServiceAccountCredential):
		writeErrorEnvelope(w, r, http.StatusUnauthorized, dto.CodeInvalidCredentials, "API key is missing, invalid, revoked, or expired.", nil)
	case errors.Is(err, entity.ErrAccountDisabled):
		writeErrorEnvelope(w, r, http.StatusForbidden, dto.CodeAccountDisabled, "This service account is disabled.", nil)
	default:
		writeServiceError(w, r, err)
	}
}
