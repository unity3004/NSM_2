package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// ServiceAccountRepository persists entity.ServiceAccount and its role
// grants — the machine-identity mirror of UserRepository.
type ServiceAccountRepository interface {
	Create(ctx context.Context, sa *entity.ServiceAccount) error
	GetByID(ctx context.Context, id string) (*entity.ServiceAccount, error)
	List(ctx context.Context, organizationID string, cursor *string, limit int) ([]*entity.ServiceAccount, error)
	Update(ctx context.Context, sa *entity.ServiceAccount) error
	Delete(ctx context.Context, id string) error
	// TouchLastAuthenticated sets last_authenticated_at to now() — called
	// only from ServiceAccountService.Authenticate's success path, never
	// from an admin operation (see entity.ServiceAccount.LastAuthenticatedAt's
	// own doc comment).
	TouchLastAuthenticated(ctx context.Context, id string) error

	GrantRole(ctx context.Context, grant *entity.ServiceAccountRole) error
	RevokeRole(ctx context.Context, serviceAccountID, roleID string) error
	ListRoles(ctx context.Context, serviceAccountID string) ([]*entity.ServiceAccountRole, error)
}
