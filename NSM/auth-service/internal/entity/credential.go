package entity

import "time"

// APIKeyStatus mirrors the api_key_status Postgres enum.
type APIKeyStatus string

const (
	APIKeyStatusActive  APIKeyStatus = "active"
	APIKeyStatusRevoked APIKeyStatus = "revoked"
	APIKeyStatusExpired APIKeyStatus = "expired"
)

// APIKey is a long-lived bearer credential owned by exactly one of a User or
// a ServiceAccount — never both, never neither (mirrors the
// ck_api_keys_single_owner CHECK constraint; HasSingleOwner lets the service
// layer reject a bad request before it ever reaches the database).
// SecretHash is never populated on read — only Create returns the raw
// secret, and only once.
type APIKey struct {
	ID                    string
	OrganizationID        string
	OwnerUserID           *string
	OwnerServiceAccountID *string
	Name                  string
	KeyPrefix             string
	KeyHash               string
	Status                APIKeyStatus
	LastUsedAt            *time.Time
	ExpiresAt             *time.Time
	CreatedAt             time.Time
	RevokedAt             *time.Time
	RevokedReason         *string
}

// HasSingleOwner enforces the XOR ownership rule in Go, ahead of the DB's
// own CHECK constraint — see entity.ErrOwnerConflict.
func (k *APIKey) HasSingleOwner() bool {
	return (k.OwnerUserID != nil) != (k.OwnerServiceAccountID != nil)
}

// APIKeyPermission is a scope attached directly to a key (api_key_permissions),
// independent of its owner's roles — a key can only narrow what its owner
// can do, never widen it.
type APIKeyPermission struct {
	APIKeyID     string
	PermissionID string
}
