package dto

import "time"

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
