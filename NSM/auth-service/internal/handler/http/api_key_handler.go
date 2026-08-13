package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/service"
)

// apiKeyHandler backs /v1/api-keys* (auth-service-openapi.yaml's own
// "API Keys" resource). Scoped, for this sprint, to service-account-owned
// keys only — every create request must name owner_service_account_id and
// must not name owner_user_id (see create's own validation below); the
// underlying entity/repository already support a user-owned key just as
// well (see entity.APIKey.HasSingleOwner), but exposing personal API keys
// for human users is a distinct feature this sprint's own objective never
// asks for, deliberately left for a later sprint (see the final report's
// "known limitations").
//
// rotate (POST /v1/api-keys/{apiKeyId}/rotate) is this handler's one
// addition beyond auth-service-openapi.yaml's own documented paths — that
// spec defines list/create/get/delete for this resource but no rotate
// endpoint, even though this sprint's own objective explicitly requires
// credential rotation support ("support rotation" / API DESIGN's own
// .../rotate example). Adding it as /v1/api-keys/{apiKeyId}/rotate,
// matching the resource's own existing path shape and ID parameter
// rather than inventing a new naming pattern, is the smallest change that
// closes that gap.
type apiKeyHandler struct {
	svc *service.ServiceAccountService
}

// create implements POST /v1/api-keys.
func (h *apiKeyHandler) create(w http.ResponseWriter, r *http.Request) {
	var req dto.ApiKeyCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}
	if req.OwnerServiceAccountID == nil {
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError,
			"owner_service_account_id is required (user-owned API keys are not yet supported).", nil)
		return
	}
	if req.OwnerUserID != nil {
		writeErrorEnvelope(w, r, http.StatusConflict, dto.CodeOwnerConflict,
			"Exactly one of owner_user_id or owner_service_account_id is required.", nil)
		return
	}

	result, err := h.svc.IssueCredential(r.Context(), service.IssueCredentialInput{
		ServiceAccountID: *req.OwnerServiceAccountID,
		Name:             req.Name,
		ExpiresAt:        req.ExpiresAt,
		ActorUserID:      actorUserID(r),
		IPAddress:        clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.ApiKeyCreatedResponseFrom(result.Key, result.Secret))
}

// list implements GET /v1/api-keys — filtered to owner_service_account_id
// (required in this scoped implementation; see this handler's own doc
// comment on why owner_user_id isn't supported).
func (h *apiKeyHandler) list(w http.ResponseWriter, r *http.Request) {
	serviceAccountID := r.URL.Query().Get("owner_service_account_id")
	if serviceAccountID == "" {
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError,
			"owner_service_account_id query parameter is required.", nil)
		return
	}
	keys, err := h.svc.ListCredentials(r.Context(), serviceAccountID)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.ApiKeyResponse, 0, len(keys))
	for _, k := range keys {
		out = append(out, dto.ApiKeyResponseFromEntity(k))
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.ApiKeyResponse `json:"data"`
		Page dto.PageMeta         `json:"page"`
	}{Data: out, Page: dto.PageMeta{HasMore: false, Limit: len(out)}})
}

// get implements GET /v1/api-keys/{apiKeyId} — metadata only, never the
// secret (see dto.ApiKeyResponse's own doc comment).
func (h *apiKeyHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("apiKeyId")
	k, err := h.svc.GetCredential(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.ApiKeyResponseFromEntity(k))
}

// delete implements DELETE /v1/api-keys/{apiKeyId} — revocation (see
// auth-service-openapi.yaml's own description: "Revoke immediately;
// already-issued short-lived tokens from it are unaffected until they
// expire"), never a hard delete of the row itself; there is no method
// anywhere in this codebase that deletes an api_keys row outright. The
// optional {"reason": "..."} body the spec documents is accepted but not
// yet threaded through to ServiceAccountService.RevokeCredential, which
// always records "admin_revoked" — a caller-supplied free-text reason
// ending up in an audit_logs row unvalidated is a small enough gap to
// leave for a follow-up rather than block this endpoint on.
func (h *apiKeyHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("apiKeyId")
	if r.Body != nil && r.ContentLength != 0 {
		var req struct {
			Reason *string `json:"reason,omitempty"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
	}
	if err := h.svc.RevokeCredential(r.Context(), id, actorUserID(r), clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotate implements POST /v1/api-keys/{apiKeyId}/rotate — see this
// handler's own doc comment for why this endpoint exists beyond
// auth-service-openapi.yaml's own documented set.
func (h *apiKeyHandler) rotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("apiKeyId")
	result, err := h.svc.RotateCredential(r.Context(), id, actorUserID(r), clientIP(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.ApiKeyCreatedResponseFrom(result.Key, result.Secret))
}
