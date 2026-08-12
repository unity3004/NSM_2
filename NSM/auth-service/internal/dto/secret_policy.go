package dto

import (
	"fmt"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// validPolicyActions is the same five-action vocabulary
// service.PolicyRuleInput.toEntity enforces (internal/entity's
// PolicyAction* constants) — duplicated here as a set literal purely so
// this file can report an unknown action as a field-level 422 without
// importing service for anything but the request/response translation it
// already needs; the service's own check remains the authoritative one
// defense-in-depth requires.
var validPolicyActions = map[string]bool{
	"read": true, "create": true, "update": true, "delete": true, "list": true,
}

// PolicyRuleRequest is one rule within a SecretPolicyCreateRequest/
// SecretPolicyUpdateRequest — matches components.schemas.SecretPolicyRule.
// Effect defaults to "allow" server-side when omitted (see
// service.PolicyRuleInput's own doc comment); the empty string is a valid
// wire value here for exactly that reason, not a validation failure.
type PolicyRuleRequest struct {
	PathPattern string   `json:"path_pattern"`
	Effect      string   `json:"effect,omitempty"`
	Actions     []string `json:"actions"`
}

// validate appends this rule's field errors to errs, each prefixed with
// its index in the parent request's Rules slice (e.g. "rules[0].actions")
// so a client can tell exactly which rule among several is malformed —
// the same per-item indexing convention this codebase has no prior
// multi-item DTO to establish a precedent from, but which
// ValidationErrors' flat field-list shape supports directly.
func (r PolicyRuleRequest) validate(index int, errs *ValidationErrors) {
	pattern := util.NormalizePolicyPathPattern(r.PathPattern)
	if err := util.ValidatePolicyPathPattern(pattern); err != nil {
		errs.Add(fmt.Sprintf("rules[%d].path_pattern", index), err.Error())
	}
	if r.Effect != "" && r.Effect != "allow" && r.Effect != "deny" {
		errs.Add(fmt.Sprintf("rules[%d].effect", index), `must be "allow" or "deny"`)
	}
	if len(r.Actions) == 0 {
		errs.Add(fmt.Sprintf("rules[%d].actions", index), "must name at least one action")
	}
	for _, a := range r.Actions {
		if !validPolicyActions[a] {
			errs.Add(fmt.Sprintf("rules[%d].actions", index), fmt.Sprintf("unknown action %q — must be one of read, create, update, delete, list", a))
			break
		}
	}
}

// SecretPolicyCreateRequest matches components.schemas.SecretPolicyCreate.
type SecretPolicyCreateRequest struct {
	Name        string              `json:"name"`
	Description *string             `json:"description,omitempty"`
	Rules       []PolicyRuleRequest `json:"rules"`
}

// Validate reuses util.ValidatePolicyPathPattern directly, the same
// "catch it here, at the DTO boundary, with a field-level message" role
// SecretCreateRequest.Validate already plays for a secret's own path
// (see that method's own doc comment) — a malformed rule is reported as a
// 422 with which rule and which field, before this ever reaches
// SecretPolicyService's own (necessarily coarser, single-error) re-validation.
func (r SecretPolicyCreateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Name) == 0 || len(r.Name) > 100 {
		errs.Add("name", "is required and must be at most 100 characters")
	}
	if len(r.Rules) == 0 {
		errs.Add("rules", "must contain at least one rule")
	}
	for i, rule := range r.Rules {
		rule.validate(i, &errs)
	}
	return errs.Err()
}

// SecretPolicyUpdateRequest matches components.schemas.SecretPolicyUpdate.
// Rules is nil-vs-empty significant, exactly mirroring
// service.UpdatePolicyInput.Rules: omitting "rules" from the request body
// entirely leaves the policy's existing rules untouched; sending
// "rules": [] is rejected the same way SecretPolicyCreateRequest rejects
// it, never silently accepted as "now grants nothing."
type SecretPolicyUpdateRequest struct {
	Name        string              `json:"name"`
	Description *string             `json:"description,omitempty"`
	Rules       []PolicyRuleRequest `json:"rules,omitempty"`
}

func (r SecretPolicyUpdateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Name) == 0 || len(r.Name) > 100 {
		errs.Add("name", "is required and must be at most 100 characters")
	}
	if r.Rules != nil {
		if len(r.Rules) == 0 {
			errs.Add("rules", "must contain at least one rule when provided")
		}
		for i, rule := range r.Rules {
			rule.validate(i, &errs)
		}
	}
	return errs.Err()
}

// SecretPolicyRuleResponse matches components.schemas.SecretPolicyRule.
type SecretPolicyRuleResponse struct {
	ID          string   `json:"id"`
	PathPattern string   `json:"path_pattern"`
	Effect      string   `json:"effect"`
	Actions     []string `json:"actions"`
}

func SecretPolicyRuleResponseFromEntity(r *entity.SecretPolicyRule) SecretPolicyRuleResponse {
	actions := make([]string, len(r.Actions))
	for i, a := range r.Actions {
		actions[i] = string(a)
	}
	return SecretPolicyRuleResponse{ID: r.ID, PathPattern: r.PathPattern, Effect: string(r.Effect), Actions: actions}
}

// SecretPolicyResponse matches components.schemas.SecretPolicy — the
// policy itself, without its rules (see SecretPolicyDetailResponse for
// the rule-bearing shape GET /v1/secret-policies/{policyId} returns).
// List responses use this narrower shape deliberately: rendering every
// policy's full rule set on the list screen is not what an admin table
// needs, the same "list is metadata, detail is the full picture" split
// SecretResponse/SecretValueResponse already draws for secrets themselves.
type SecretPolicyResponse struct {
	ID             string    `json:"id"`
	OrganizationID *string   `json:"organization_id,omitempty"`
	Name           string    `json:"name"`
	Description    *string   `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func SecretPolicyResponseFromEntity(p *entity.SecretPolicy) SecretPolicyResponse {
	return SecretPolicyResponse{
		ID:             p.ID,
		OrganizationID: p.OrganizationID,
		Name:           p.Name,
		Description:    p.Description,
		CreatedAt:      p.CreatedAt,
		UpdatedAt:      p.UpdatedAt,
	}
}

// SecretPolicyDetailResponse is GET /v1/secret-policies/{policyId}'s body
// — SecretPolicyResponse plus its full rule set, matching
// components.schemas.SecretPolicyDetail and the same "detail bundles what
// an admin UI needs in one call" reasoning RoleWithPermissionsResponse
// already documents for roles.
type SecretPolicyDetailResponse struct {
	SecretPolicyResponse
	Rules []SecretPolicyRuleResponse `json:"rules"`
}

func SecretPolicyDetailResponseFrom(detail service.PolicyDetail) SecretPolicyDetailResponse {
	rules := make([]SecretPolicyRuleResponse, 0, len(detail.Rules))
	for _, r := range detail.Rules {
		rules = append(rules, SecretPolicyRuleResponseFromEntity(r))
	}
	return SecretPolicyDetailResponse{SecretPolicyResponse: SecretPolicyResponseFromEntity(detail.Policy), Rules: rules}
}

// SecretPolicyAssignmentRequest matches
// components.schemas.SecretPolicyAssignmentCreate — the body of
// POST /v1/secret-policies/{policyId}/assignments.
type SecretPolicyAssignmentRequest struct {
	RoleID string `json:"role_id"`
}

func (r SecretPolicyAssignmentRequest) Validate() error {
	var errs ValidationErrors
	if r.RoleID == "" {
		errs.Add("role_id", "is required")
	}
	return errs.Err()
}
