package service

import (
	"context"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
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

// RegistrationTxFunc runs fn against a transaction-scoped UserRepository
// and AuditLogRepository — the user-creation write and the audit-event
// write succeed together or not at all. It's expressed purely in terms of
// this package's own repository interfaces, never database/sql or
// repository/postgres, so internal/service keeps the property the rest of
// this codebase relies on (see README.md: "internal/service imports
// entity and repository — an interface — never repository/postgres
// directly"). cmd/server/main.go supplies the concrete closure, backed by
// database.WithTx and the real Postgres repository constructors — it's
// already the one place in the whole service allowed to know about both.
type RegistrationTxFunc func(ctx context.Context, fn func(repository.UserRepository, repository.AuditLogRepository) error) error

type UserService struct {
	users      repository.UserRepository
	passwords  *security.PasswordService
	registerTx RegistrationTxFunc
}

// NewUserService's registerTx may be nil if the binary wiring it up never
// calls Register (e.g. a future admin-only build) — every other method
// only needs users/passwords, unchanged from before this milestone.
func NewUserService(users repository.UserRepository, passwords *security.PasswordService, registerTx RegistrationTxFunc) *UserService {
	return &UserService{users: users, passwords: passwords, registerTx: registerTx}
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

// RegisterInput is Register's argument — deliberately its own type rather
// than a bare *entity.User, the same way dto.RegisterRequest is its own
// type rather than dto.UserCreateRequest: registration is a distinct use
// case (self-service, always all three fields, never an invite/SSO
// variant) from the admin-facing CreateUser above, even though both end
// up calling the same PasswordService and the same repository.
type RegisterInput struct {
	OrganizationID string
	Username       string
	Email          string
	Password       string
	IPAddress      string
}

// Register implements POST /auth/register: hash the password, create the
// user and record a "user.registered" audit event atomically, and return
// the created user. It never returns a token, session, or anything else
// that would constitute logging the caller in — registration and
// authentication are separate acts (see auth-architecture-sprint2.md's
// scope note on why this sprint doesn't auto-login after registration).
//
// Status is set to Active immediately, not PendingVerification: nothing
// in this build yet moves an account *out* of PendingVerification (email
// verification is explicitly deferred — see the doc comment on
// entity.UserStatusPendingVerification's sibling values), so using it here
// would strand every registered account in a status that can never
// resolve and that Login doesn't even gate on today. Active is the
// honest description of what this milestone actually does; wiring in
// PendingVerification is this method's job to change, not Login's, once a
// verification flow exists.
func (s *UserService) Register(ctx context.Context, in RegisterInput) (*entity.User, error) {
	hash, err := s.passwords.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	// Hashing happens before the transaction opens, deliberately: Argon2id
	// is supposed to be expensive (tens of milliseconds of CPU and tens of
	// MiB of memory per call — see security.DefaultParams), and holding a
	// Postgres transaction open for the duration of the request's single
	// most expensive step would tie up a connection-pool slot and any row
	// locks for no consistency benefit — nothing inside the transaction
	// depends on how the hash was computed, only on its final value.
	algo := passwordAlgoArgon2id
	username := in.Username
	email := util.NormalizeEmail(in.Email)

	user := &entity.User{
		OrganizationID: in.OrganizationID,
		Email:          email,
		Username:       &username,
		PasswordHash:   &hash,
		PasswordAlgo:   &algo,
		Status:         entity.UserStatusActive,
	}

	err = s.registerTx(ctx, func(users repository.UserRepository, audit repository.AuditLogRepository) error {
		if err := users.Create(ctx, user); err != nil {
			return err
		}
		// Metadata carries only what's safe to have sitting in a JSONB
		// column indefinitely — username and (normalized) email, both
		// already visible elsewhere on the user record. It must never
		// carry `password` or `hash`; there is no path from `in.Password`
		// or `hash` (above) into this map, and there must never be one.
		entry := &entity.AuditLogEntry{
			OrganizationID: &in.OrganizationID,
			ActorType:      entity.AuditActorUser,
			ActorID:        &user.ID,
			Action:         "user.registered",
			ResourceType:   strPtr("user"),
			ResourceID:     &user.ID,
			Result:         entity.AuditResultSuccess,
			IPAddress:      strPtr(in.IPAddress),
			Metadata: map[string]any{
				"username": username,
				"email":    email,
			},
		}
		return audit.Append(ctx, entry)
	})
	if err != nil {
		return nil, err
	}

	logging.FromContext(ctx).Info("user registered",
		zap.String("user_id", user.ID), zap.String("organization_id", in.OrganizationID))
	return user, nil
}
