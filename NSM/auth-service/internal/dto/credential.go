package dto

import (
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// ApiKeyCreateRequest matches components.schemas.ApiKeyCreate. Exactly one
// of OwnerUserID / OwnerServiceAccountID must be set — validated here for a
// fast 422, and again by entity.APIKey.HasSingleOwner before the insert.
type ApiKeyCreateRequest struct {
	Name                  string     `json:"name"`
	OwnerUserID           *string    `json:"owner_user_id,omitempty"`
	OwnerServiceAccountID *string    `json:"owner_service_account_id,omitempty"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	PermissionIDs         []string   `json:"permission_ids,omitempty"`
}

func (r ApiKeyCreateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Name) == 0 || len(r.Name) > 150 {
		errs.Add("name", "is required and must be at most 150 characters")
	}
	hasUser := r.OwnerUserID != nil
	hasSvcAcct := r.OwnerServiceAccountID != nil
	if hasUser == hasSvcAcct {
		errs.Add("owner_user_id", "exactly one of owner_user_id or owner_service_account_id is required")
	}
	return errs.Err()
}

// ApiKeyResponse matches components.schemas.ApiKey — metadata only, never
// the secret (see ApiKeyCreatedResponse for the one exception).
type ApiKeyResponse struct {
	ID                    string     `json:"id"`
	OrganizationID        string     `json:"organization_id"`
	OwnerUserID           *string    `json:"owner_user_id,omitempty"`
	OwnerServiceAccountID *string    `json:"owner_service_account_id,omitempty"`
	Name                  string     `json:"name"`
	KeyPrefix             string     `json:"key_prefix"`
	Status                string     `json:"status"`
	LastUsedAt            *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	RevokedAt             *time.Time `json:"revoked_at,omitempty"`
	RevokedReason         *string    `json:"revoked_reason,omitempty"`
}

// ApiKeyCreatedResponse matches components.schemas.ApiKeyCreated — the only
// response in the whole API that carries Secret.
type ApiKeyCreatedResponse struct {
	ApiKeyResponse
	Secret string `json:"secret"`
}

// ApiKeyResponseFromEntity converts entity.APIKey to the wire shape —
// KeyHash is deliberately not one of ApiKeyResponse's fields at all (see
// that type's own doc comment), so there is no field of this function's
// return value it could even be assigned to.
func ApiKeyResponseFromEntity(k *entity.APIKey) ApiKeyResponse {
	return ApiKeyResponse{
		ID:                    k.ID,
		OrganizationID:        k.OrganizationID,
		OwnerUserID:           k.OwnerUserID,
		OwnerServiceAccountID: k.OwnerServiceAccountID,
		Name:                  k.Name,
		KeyPrefix:             k.KeyPrefix,
		Status:                string(k.Status),
		LastUsedAt:            k.LastUsedAt,
		ExpiresAt:             k.ExpiresAt,
		CreatedAt:             k.CreatedAt,
		RevokedAt:             k.RevokedAt,
		RevokedReason:         k.RevokedReason,
	}
}

// ApiKeyCreatedResponseFrom builds the one response that carries secret —
// callers must supply it explicitly (never read off k, which never holds
// a raw secret in the first place — see entity.APIKey's own doc comment)
// so there is no path through this function that could accidentally leak
// a hash in secret's place.
func ApiKeyCreatedResponseFrom(k *entity.APIKey, secret string) ApiKeyCreatedResponse {
	return ApiKeyCreatedResponse{ApiKeyResponse: ApiKeyResponseFromEntity(k), Secret: secret}
}
