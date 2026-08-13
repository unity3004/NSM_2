package dto

import (
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// ServiceAccountCreateRequest matches components.schemas.ServiceAccountCreate
// (auth-service-openapi.yaml).
type ServiceAccountCreateRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

func (r ServiceAccountCreateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Name) == 0 || len(r.Name) > 150 {
		errs.Add("name", "is required and must be at most 150 characters")
	}
	if r.Description != nil && len(*r.Description) > 500 {
		errs.Add("description", "must be at most 500 characters")
	}
	return errs.Err()
}

// ServiceAccountUpdateRequest matches components.schemas.ServiceAccountUpdate.
// Status is optional — when set, the handler routes it through
// ServiceAccountService.DisableServiceAccount/EnableServiceAccount (which
// also revoke active credentials on disable) rather than a raw column
// write, so a status change made via PATCH gets the identical side effects
// a dedicated disable/enable call would.
type ServiceAccountUpdateRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Status      *string `json:"status,omitempty"`
}

func (r ServiceAccountUpdateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Name) == 0 || len(r.Name) > 150 {
		errs.Add("name", "is required and must be at most 150 characters")
	}
	if r.Description != nil && len(*r.Description) > 500 {
		errs.Add("description", "must be at most 500 characters")
	}
	if r.Status != nil {
		s := entity.ServiceAccountStatus(*r.Status)
		if s != entity.ServiceAccountStatusActive && s != entity.ServiceAccountStatusDisabled {
			errs.Add("status", `must be "active" or "disabled"`)
		}
	}
	return errs.Err()
}

// ServiceAccountResponse matches components.schemas.ServiceAccount, plus
// last_authenticated_at — an additive field beyond the original spec
// (which predates entity.ServiceAccount.LastAuthenticatedAt) that this
// sprint's own objective explicitly requires surfacing ("Display: ...
// last authentication"). Existing clients that only know the original
// schema are unaffected; it's one more optional field, never a removed
// or renamed one.
type ServiceAccountResponse struct {
	ID                  string     `json:"id"`
	OrganizationID      string     `json:"organization_id"`
	Name                string     `json:"name"`
	Description         *string    `json:"description,omitempty"`
	Status              string     `json:"status"`
	CreatedBy           *string    `json:"created_by,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastAuthenticatedAt *time.Time `json:"last_authenticated_at,omitempty"`
}

func ServiceAccountResponseFromEntity(sa *entity.ServiceAccount) ServiceAccountResponse {
	return ServiceAccountResponse{
		ID:                  sa.ID,
		OrganizationID:      sa.OrganizationID,
		Name:                sa.Name,
		Description:         sa.Description,
		Status:              string(sa.Status),
		CreatedBy:           sa.CreatedBy,
		CreatedAt:           sa.CreatedAt,
		UpdatedAt:           sa.UpdatedAt,
		LastAuthenticatedAt: sa.LastAuthenticatedAt,
	}
}

// ServiceAccountDetailResponse is GET /v1/service-accounts/{id}'s body —
// the service account plus its current role grants and the permissions
// those roles confer, the same "detail view resolves roles/permissions
// too" shape dto.UserDetailResponse already establishes for users.
type ServiceAccountDetailResponse struct {
	ServiceAccountResponse
	Roles       []RoleGrantResponse  `json:"roles"`
	Permissions []PermissionResponse `json:"permissions"`
}

// ServiceAccountTokenRequest matches POST /service-accounts/{id}/token's
// (optional) request body. RequestedTTLSeconds is accepted for wire
// compatibility with the OpenAPI spec's own schema — decodeJSON's strict
// DisallowUnknownFields would otherwise reject a spec-following client's
// request outright — but is deliberately never honored as a longer-than-
// configured override: util.JWTSigner (and security.TokenService
// alongside it) both already make "no per-call TTL override" a fixed
// design decision for the identical security reason ("nothing downstream
// can ever request a longer-lived token than the service's own
// configuration allows" — see TokenService.own doc comment), and this
// sprint's own "do not create unnecessarily long-lived bearer
// credentials" instruction is exactly that same rule applied to machine
// tokens. If present, it is validated against the spec's own bounds
// (60-3600s) purely so a malformed value gets a clear 422 rather than
// being silently ignored, but the token's actual lifetime is always
// cfg.JWT.AccessTokenTTL — the same fixed value human access tokens use.
type ServiceAccountTokenRequest struct {
	RequestedTTLSeconds *int `json:"requested_ttl_seconds,omitempty"`
}

func (r ServiceAccountTokenRequest) Validate() error {
	var errs ValidationErrors
	if r.RequestedTTLSeconds != nil && (*r.RequestedTTLSeconds < 60 || *r.RequestedTTLSeconds > 3600) {
		errs.Add("requested_ttl_seconds", "must be between 60 and 3600")
	}
	return errs.Err()
}
