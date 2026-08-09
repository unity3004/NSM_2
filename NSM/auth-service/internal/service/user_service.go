package service

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/security"
)

// passwordAlgoArgon2id is the value stored in users.password_algo for
// hashes CreateUser produces. It's a local literal rather than an
// exported constant on security.PasswordService because this change is
// scoped to this file, auth_service.go, auth_service_test.go, and
// main.go only — adding a new exported name to internal/security is a
// natural follow-up (it would remove the need to keep this string in sync
// with the "argon2id" tag security.decodeHash expects by hand) but is a
// fifth file, not one of the four this change touches.
const passwordAlgoArgon2id = "argon2id"

type UserService struct {
	users     repository.UserRepository
	passwords *security.PasswordService
}

func NewUserService(users repository.UserRepository, passwords *security.PasswordService) *UserService {
	return &UserService{users: users, passwords: passwords}
}

// CreateUser hashes the password (if any — an SSO-only account has none)
// before it ever reaches the repository, so no repository implementation
// can accidentally persist a plaintext one.
func (s *UserService) CreateUser(ctx context.Context, u *entity.User, plaintextPassword *string) (*entity.User, error) {
	if plaintextPassword != nil {
		hash, err := s.passwords.Hash(*plaintextPassword)
		if err != nil {
			return nil, err
		}
		algo := passwordAlgoArgon2id
		u.PasswordHash = &hash
		u.PasswordAlgo = &algo
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserService) GetUser(ctx context.Context, id string) (*entity.User, error) {
	return s.users.GetByID(ctx, id)
}

func (s *UserService) ListUsers(ctx context.Context, organizationID string, f repository.UserFilter) ([]*entity.User, error) {
	return s.users.List(ctx, organizationID, f)
}

func (s *UserService) UpdateUser(ctx context.Context, u *entity.User) error {
	return s.users.Update(ctx, u)
}

func (s *UserService) DeleteUser(ctx context.Context, id string) error {
	return s.users.SoftDelete(ctx, id)
}
