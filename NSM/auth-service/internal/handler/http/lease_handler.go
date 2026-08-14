package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/service"
)

// leaseHandler translates HTTP requests into service.LeaseService calls
// and service results back into dto.* JSON — nothing else, the same
// narrow translation-only role every other handler in this package
// plays. It never generates a credential, evaluates a policy, or writes
// an audit event itself: LeaseService already does all of that
// internally (see that type's own doc comment).
type leaseHandler struct {
	svc *service.LeaseService
}

// actor resolves the caller's LeaseIdentity from their verified claims —
// never from anything the request body supplies, the same "identity
// comes from the token, not the payload" rule every other handler in
// this codebase already follows.
func actor(r *http.Request) service.LeaseIdentity {
	identityType := entity.LeaseOwnerUser
	if isServiceAccount(r) {
		identityType = entity.LeaseOwnerServiceAccount
	}
	return service.LeaseIdentity{Type: identityType, ID: actorUserID(r)}
}

// create implements POST /v1/leases.
func (h *leaseHandler) create(w http.ResponseWriter, r *http.Request) {
	var req dto.LeaseCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}
	ttl, err := req.ParsedTTL()
	if err != nil {
		// Validate already re-parses and would have caught this — this
		// branch exists only as defense-in-depth, the same "the DTO
		// layer normally catches this, but never trust that alone"
		// precedent util.ErrInvalidSecretPath's own case in
		// writeServiceError already establishes.
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "Invalid ttl.", nil)
		return
	}

	var role string
	if req.Role != nil {
		role = *req.Role
	}
	result, err := h.svc.Create(r.Context(), service.CreateLeaseInput{
		OrganizationID: organizationIDFromRequest(r),
		LeaseType:      req.Type,
		ResourcePath:   req.Path,
		RequestedTTL:   ttl,
		Renewable:      req.Renewable,
		Role:           role,
		Actor:          actor(r),
		IPAddress:      clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.LeaseCreatedResponse{
		LeaseResponse: dto.LeaseResponseFromEntity(result.Lease),
		Credential:    result.Credential.Secret,
	})
}

// get implements GET /v1/leases/{leaseId} — metadata only, never the
// credential (see dto.LeaseResponse's own doc comment).
func (h *leaseHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("leaseId")
	lease, err := h.svc.Get(r.Context(), id, actor(r), clientIP(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.LeaseResponseFromEntity(lease))
}

// list implements GET /v1/leases — every lease actor.List's own
// visibility rule allows: every lease in the caller's organization if
// they hold leases:read, otherwise only their own.
func (h *leaseHandler) list(w http.ResponseWriter, r *http.Request) {
	leases, err := h.svc.List(r.Context(), organizationIDFromRequest(r), actor(r), repository.LeaseFilter{Limit: 50})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.LeaseResponse, 0, len(leases))
	for _, l := range leases {
		out = append(out, dto.LeaseResponseFromEntity(l))
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.LeaseResponse `json:"data"`
		Page dto.PageMeta        `json:"page"`
	}{Data: out, Page: dto.PageMeta{HasMore: false, Limit: 50}})
}

// renew implements POST /v1/leases/{leaseId}/renew.
func (h *leaseHandler) renew(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("leaseId")

	var req dto.LeaseRenewRequest
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
		if err := req.Validate(); err != nil {
			writeValidationError(w, r, err)
			return
		}
	}
	ttl, err := req.ParsedTTL()
	if err != nil {
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "Invalid ttl.", nil)
		return
	}

	lease, err := h.svc.Renew(r.Context(), id, ttl, actor(r), clientIP(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.LeaseResponseFromEntity(lease))
}

// revoke implements POST /v1/leases/{leaseId}/revoke.
func (h *leaseHandler) revoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("leaseId")
	var req dto.LeaseRevokeRequest
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}
	if err := h.svc.Revoke(r.Context(), id, req.Reason, actor(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
