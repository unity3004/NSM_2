package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/service"
)

// secretPolicyHandler translates HTTP requests into
// service.SecretPolicyService calls and service results back into dto.*
// JSON — nothing else, the same narrow translation-only role secretHandler
// plays for /v1/secrets (see that type's own doc comment). It never
// evaluates a policy itself: authorization decisions live in
// internal/policy and SecretPolicyService, reached only through
// SecretService for the secrets endpoints themselves — this handler exists
// purely for administrators to manage the policies those decisions consult.
type secretPolicyHandler struct {
	svc *service.SecretPolicyService
}

// create implements POST /v1/secret-policies.
func (h *secretPolicyHandler) create(w http.ResponseWriter, r *http.Request) {
	var req dto.SecretPolicyCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	description := ""
	if req.Description != nil {
		description = *req.Description
	}

	p, err := h.svc.CreatePolicy(r.Context(), service.CreatePolicyInput{
		OrganizationID: organizationIDFromRequest(r),
		Name:           req.Name,
		Description:    description,
		Rules:          rulesToInputsFromRequest(req.Rules),
		ActorUserID:    actorUserID(r),
		IPAddress:      clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.SecretPolicyResponseFromEntity(p))
}

// get implements GET /v1/secret-policies/{policyId} — the policy plus its
// full rule set (dto.SecretPolicyDetailResponse).
func (h *secretPolicyHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("policyId")
	detail, err := h.svc.GetPolicy(r.Context(), actorUserID(r), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.SecretPolicyDetailResponseFrom(detail))
}

// list implements GET /v1/secret-policies — every policy visible to the
// caller's organization (tenant-defined plus platform-wide; see
// repository.SecretPolicyRepository.List's own doc comment), metadata
// only (no rules) the same way secretHandler.list returns metadata only
// for secrets themselves.
func (h *secretPolicyHandler) list(w http.ResponseWriter, r *http.Request) {
	policies, err := h.svc.ListPolicies(r.Context(), actorUserID(r), organizationIDFromRequest(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.SecretPolicyResponse, 0, len(policies))
	for _, p := range policies {
		out = append(out, dto.SecretPolicyResponseFromEntity(p))
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.SecretPolicyResponse `json:"data"`
	}{Data: out})
}

// update implements PUT /v1/secret-policies/{policyId}.
func (h *secretPolicyHandler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("policyId")
	var req dto.SecretPolicyUpdateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	description := ""
	if req.Description != nil {
		description = *req.Description
	}

	p, err := h.svc.UpdatePolicy(r.Context(), service.UpdatePolicyInput{
		PolicyID:    id,
		Name:        req.Name,
		Description: description,
		Rules:       rulesToInputsFromRequest(req.Rules),
		ActorUserID: actorUserID(r),
		IPAddress:   clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.SecretPolicyResponseFromEntity(p))
}

// delete implements DELETE /v1/secret-policies/{policyId} — a hard delete
// (repository.SecretPolicyRepository.Delete cascades to the policy's
// rules, their actions, and every role assignment; see migrations/000027's
// own doc comment) — unlike secrets themselves, a policy carries no
// sensitive value a soft-delete's audit trail would need to preserve.
func (h *secretPolicyHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("policyId")
	if err := h.svc.DeletePolicy(r.Context(), actorUserID(r), id, clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// assign implements POST /v1/secret-policies/{policyId}/assignments.
func (h *secretPolicyHandler) assign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("policyId")
	var req dto.SecretPolicyAssignmentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}
	if err := h.svc.AssignToRole(r.Context(), actorUserID(r), id, req.RoleID, clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// unassign implements DELETE /v1/secret-policies/{policyId}/assignments/{roleId}.
func (h *secretPolicyHandler) unassign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("policyId")
	roleID := r.PathValue("roleId")
	if err := h.svc.UnassignFromRole(r.Context(), actorUserID(r), id, roleID, clientIP(r)); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listAssignments implements GET /v1/secret-policies/{policyId}/assignments
// — every role ID this policy is currently assigned to.
func (h *secretPolicyHandler) listAssignments(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("policyId")
	roleIDs, err := h.svc.ListAssignedRoleIDs(r.Context(), actorUserID(r), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []string `json:"data"`
	}{Data: append([]string{}, roleIDs...)})
}

func rulesToInputsFromRequest(rules []dto.PolicyRuleRequest) []service.PolicyRuleInput {
	if rules == nil {
		return nil
	}
	out := make([]service.PolicyRuleInput, len(rules))
	for i, r := range rules {
		out[i] = service.PolicyRuleInput{PathPattern: r.PathPattern, Effect: r.Effect, Actions: r.Actions}
	}
	return out
}
