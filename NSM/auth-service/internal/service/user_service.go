package service

import (
	"context"
	"time"

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
	sessions   repository.SessionRepository
	passwords  *security.PasswordService
	registerTx RegistrationTxFunc
	// auditTx backs every admin-initiated action's audit event
	// (user.created, user.disabled, user.enabled, role.assigned,
	// role.removed) — best-effort, logged-and-swallowed on failure, the
	// same AuditTxFunc pattern AuthService/RefreshTokenService/LogoutService
	// already use for their own audit writes, rather than the harder
	// same-transaction guarantee Register/BootstrapService make for their
	// own single, one-time creation events. May be nil, the same
	// allowance every other AuditTx dependency in this codebase makes.
	auditTx AuditTxFunc
}

// NewUserService's registerTx may be nil if the binary wiring it up never
// calls Register (e.g. a future admin-only build) — every other method
// only needs users/passwords, unchanged from before this milestone.
func NewUserService(users repository.UserRepository, sessions repository.SessionRepository, passwords *security.PasswordService, registerTx RegistrationTxFunc, auditTx AuditTxFunc) *UserService {
	return &UserService{users: users, sessions: sessions, passwords: passwords, registerTx: registerTx, auditTx: auditTx}
}

// CreateUserInput is CreateUser's argument — the admin/invite path
// (POST /v1/users), distinct from RegisterInput's self-service path even
// though both end up hashing a password through the same PasswordService
// and calling the same UserRepository.Create. ActorUserID/IPAddress exist
// only to attribute the resulting "user.created" audit event; neither
// reaches entity.User or any password-handling code.
type CreateUserInput struct {
	User              *entity.User
	PlaintextPassword *string
	ActorUserID       string
	IPAddress         string
}

// CreateUser hashes the password (if any — an SSO-only account has none)
// before it ever reaches the repository, so no repository implementation
// can accidentally persist a plaintext one.
func (s *UserService) CreateUser(ctx context.Context, in CreateUserInput) (*entity.User, error) {
	if in.PlaintextPassword != nil {
		hash, err := s.passwords.Hash(*in.PlaintextPassword)
		if err != nil {
			return nil, err
		}
		algo := passwordAlgoArgon2id
		in.User.PasswordHash = &hash
		in.User.PasswordAlgo = &algo
	}
	if err := s.users.Create(ctx, in.User); err != nil {
		return nil, err
	}
	s.recordUserAudit(ctx, "user.created", in.ActorUserID, in.User.ID, in.IPAddress, map[string]any{
		"email": in.User.Email,
	})
	return in.User, nil
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

func (s *UserService) DeleteUser(ctx context.Context, id, actorUserID, ipAddress string) error {
	if err := s.users.SoftDelete(ctx, id); err != nil {
		return err
	}
	s.recordUserAudit(ctx, "user.deleted", actorUserID, id, ipAddress, nil)
	return nil
}

// DisableUser sets status to Disabled and revokes every one of the
// user's currently active sessions (reusing SessionRepository.RevokeAllForUser
// as-is — no new revocation mechanism). This is what actually stops
// further access, immediately: AuthService.Login already rejects a
// Disabled account outright (entity.ErrAccountDisabled), and
// RefreshTokenService.Refresh checks the session's live state before
// rotating, so a revoked session can never be used to mint a new access
// token either. The one thing this does *not* revoke is an access token
// already issued before the disable — see this method's own doc comment
// in the final report for why that is a real, already-documented
// characteristic of this service's stateless-JWT access tokens (15-minute
// default TTL), not something disabling a user is expected to reach back
// in time and undo.
func (s *UserService) DisableUser(ctx context.Context, userID, actorUserID, ipAddress string) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	u.Status = entity.UserStatusDisabled
	if err := s.users.Update(ctx, u); err != nil {
		return err
	}
	if err := s.sessions.RevokeAllForUser(ctx, userID, entity.RevocationAdminRevoked); err != nil {
		// Best-effort: the account is already disabled (Login already
		// rejects it), so a failure here narrows to "an existing refresh
		// token could still rotate until it separately expires" rather
		// than "the account can still be used to log in" — worth an
		// Error log, not a reason to report the whole operation failed
		// when the status change itself already succeeded.
		logging.FromContext(ctx).Error("failed to revoke sessions after disabling user",
			zap.String("user_id", userID), zap.Error(err))
	}
	s.recordUserAudit(ctx, "user.disabled", actorUserID, userID, ipAddress, nil)
	return nil
}

// EnableUser reverses DisableUser's status change. It does not, and
// cannot, restore sessions DisableUser revoked — a re-enabled user logs
// in again like any account establishing a new session, never resumes an
// old one.
func (s *UserService) EnableUser(ctx context.Context, userID, actorUserID, ipAddress string) error {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	u.Status = entity.UserStatusActive
	if err := s.users.Update(ctx, u); err != nil {
		return err
	}
	s.recordUserAudit(ctx, "user.enabled", actorUserID, userID, ipAddress, nil)
	return nil
}

// AssignRole grants roleID to userID, reusing UserRepository.GrantRole
// exactly as bootstrap's own role grant does — no second role-assignment
// code path. actorUserID is recorded as both the audit actor and
// user_roles.assigned_by (entity.UserRole.AssignedBy), the same "who
// performed this" provenance every other grant already carries.
func (s *UserService) AssignRole(ctx context.Context, userID, roleID, actorUserID, ipAddress string, expiresAt *time.Time) error {
	grant := &entity.UserRole{UserID: userID, RoleID: roleID, AssignedBy: &actorUserID, ExpiresAt: expiresAt}
	if err := s.users.GrantRole(ctx, grant); err != nil {
		return err
	}
	s.recordUserAudit(ctx, "role.assigned", actorUserID, userID, ipAddress, map[string]any{"role_id": roleID})
	return nil
}

// RemoveRole revokes roleID from userID.
func (s *UserService) RemoveRole(ctx context.Context, userID, roleID, actorUserID, ipAddress string) error {
	if err := s.users.RevokeRole(ctx, userID, roleID); err != nil {
		return err
	}
	s.recordUserAudit(ctx, "role.removed", actorUserID, userID, ipAddress, map[string]any{"role_id": roleID})
	return nil
}

// ListUserRoles returns userID's current (non-expired) direct role
// grants — a thin pass-through to UserRepository.ListRoles, kept on this
// service so handlers never call a repository directly.
func (s *UserService) ListUserRoles(ctx context.Context, userID string) ([]*entity.UserRole, error) {
	return s.users.ListRoles(ctx, userID)
}

// recordUserAudit is best-effort and never surfaces a failure to the
// caller — the same convention every other audit write in this codebase
// follows (see AuthService.recordLoginAudit). metadata may be nil for
// actions (disable/enable) that need no extra context beyond actor,
// action, and resource.
func (s *UserService) recordUserAudit(ctx context.Context, action, actorUserID, targetUserID, ipAddress string, metadata map[string]any) {
	if s.auditTx == nil {
		return
	}
	var actorID *string
	if actorUserID != "" {
		actorID = &actorUserID
	}
	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    entity.AuditActorUser,
			ActorID:      actorID,
			Action:       action,
			ResourceType: strPtr("user"),
			ResourceID:   strPtr(targetUserID),
			Result:       entity.AuditResultSuccess,
			IPAddress:    strPtr(ipAddress),
			RequestID:    strPtr(util.RequestIDFromContext(ctx)),
			Metadata:     metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record audit event",
			zap.String("action", action), zap.Error(err))
	}
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
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
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
