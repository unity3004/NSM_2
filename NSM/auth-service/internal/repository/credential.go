package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// ApiKeyFilter narrows GET /api-keys.
type ApiKeyFilter struct {
	OwnerUserID           *string
	OwnerServiceAccountID *string
	Status                *entity.APIKeyStatus
	Cursor                *string
	Limit                 int
}

// APIKeyRepository persists entity.APIKey and its own scopes. There is no
// method that returns a stored secret — only KeyHash is ever read back,
// because only KeyHash is ever written.
type APIKeyRepository interface {
	Create(ctx context.Context, k *entity.APIKey) error
	GetByID(ctx context.Context, id string) (*entity.APIKey, error)
	GetByKeyHash(ctx context.Context, keyHash string) (*entity.APIKey, error)
	List(ctx context.Context, organizationID string, f ApiKeyFilter) ([]*entity.APIKey, error)
	Revoke(ctx context.Context, id string, reason *string) error
	TouchLastUsed(ctx context.Context, id string) error

	AddPermission(ctx context.Context, p *entity.APIKeyPermission) error
	RemovePermission(ctx context.Context, apiKeyID, permissionID string) error
	ListPermissions(ctx context.Context, apiKeyID string) ([]*entity.Permission, error)
}
