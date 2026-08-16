// Package repository declares the ports the service layer depends on —
// interfaces only, no SQL. This is the Dependency Inversion half of Clean
// Architecture: internal/service imports this package (an abstraction);
// internal/repository/postgres implements it (a detail). Swapping Postgres
// for anything else — a different driver, an in-memory fake for tests —
// never requires touching internal/service.
package repository

import (
	"context"
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// UserRepository persists entity.User and its direct role grants
// (entity.UserRole).
type UserRepository interface {
	Create(ctx context.Context, u *entity.User) error
	GetByID(ctx context.Context, id string) (*entity.User, error)
	GetByEmail(ctx context.Context, organizationID, email string) (*entity.User, error)
	List(ctx context.Context, organizationID string, f UserFilter) ([]*entity.User, error)
	Update(ctx context.Context, u *entity.User) error
	SoftDelete(ctx context.Context, id string) error

	IncrementFailedLoginAttempts(ctx context.Context, id string) (attempts int, err error)
	ResetFailedLoginAttempts(ctx context.Context, id string) error
	Lock(ctx context.Context, id string, until time.Time) error

	GrantRole(ctx context.Context, grant *entity.UserRole) error
	RevokeRole(ctx context.Context, userID, roleID string) error
	ListRoles(ctx context.Context, userID string) ([]*entity.UserRole, error)
}

// UserFilter narrows GET /users. Zero value means "no filter".
type UserFilter struct {
	Status *entity.UserStatus
	Email  *string
	Cursor *string
	Limit  int
}
