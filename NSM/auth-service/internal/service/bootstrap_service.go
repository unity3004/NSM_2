package service

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/util"
)

// platformAdminRoleID is the fixed, well-known role ID seeded by
// migrations/000021_seed_platform_admin_role.up.sql. Bootstrap grants
// exactly this role rather than creating one of its own — see that
// migration's own doc comment for why "the first administrator's role"
// and "the row an operator finds in the roles table" must be the same
// row, not two roles that happen to have the same name.
const platformAdminRoleID = "00000000-0000-4000-9000-000000000001"

const (
	defaultOrganizationName = "Default Organization"
	defaultOrganizationSlug = "default"
)

// ErrAlreadyInitialized is returned when a bootstrap attempt loses the
// race, or simply arrives after a real prior bootstrap. It is literally
// entity.ErrAlreadyExists, not a new sentinel wrapping it: the one
// resource this operation creates — an initialized platform — already
// exists, which is exactly what that existing sentinel means, and
// writeServiceError already maps it to 409 CONFLICT with zero changes to
// response.go needed.
var ErrAlreadyInitialized = entity.ErrAlreadyExists

// BootstrapTxFunc runs fn against a transaction-scoped
// PlatformBootstrapRepository, OrganizationRepository, UserRepository, and
// AuditLogRepository — every write a successful bootstrap makes (the
// uninitialized->initialized state transition, the organization if one
// didn't already exist, the administrator user, its role grant, and the
// "platform.initialized" audit event) commits or rolls back together, the
// same all-or-nothing guarantee UserService's RegistrationTxFunc already
// gives POST /auth/register.
type BootstrapTxFunc func(ctx context.Context, fn func(repository.PlatformBootstrapRepository, repository.OrganizationRepository, repository.UserRepository, repository.AuditLogRepository) error) error

// BootstrapService implements the platform's one-time first-administrator
// setup flow.
type BootstrapService struct {
	passwords *security.PasswordService
	// platform is a plain, non-transactional repository — used only by
	// Initialized's status read, which must never block behind a
	// concurrent bootstrap attempt's row lock (see
	// PlatformBootstrapRepository.LockForBootstrap).
	platform repository.PlatformBootstrapRepository
	// bootstrapTx is the atomic write path — see BootstrapTxFunc.
	bootstrapTx BootstrapTxFunc
	// rejectionAuditTx records a rejected attempt in its own transaction,
	// deliberately outside bootstrapTx's — see Bootstrap's doc comment on
	// why that write can't live inside the transaction that's rolling
	// back. May be nil, the same "audit logging is best-effort and
	// optional to wire up" allowance AuthServiceDeps.AuditTx already
	// makes.
	rejectionAuditTx AuditTxFunc
	// abuseProtection reuses the exact same Redis-backed abuse-protection
	// component AuthService.Login and RefreshTokenService.Refresh already
	// use — a new ratelimit.OperationBootstrap operation name, not a new
	// rate-limiting mechanism. Every current caller in cmd/server/main.go
	// passes the one shared instance, the same way Login and Refresh
	// already do.
	abuseProtection     ratelimit.AuthAbuseProtection
	rateLimitRetryAfter time.Duration
}

func NewBootstrapService(
	passwords *security.PasswordService,
	platform repository.PlatformBootstrapRepository,
	bootstrapTx BootstrapTxFunc,
	rejectionAuditTx AuditTxFunc,
	abuseProtection ratelimit.AuthAbuseProtection,
	rateLimitRetryAfter time.Duration,
) *BootstrapService {
	return &BootstrapService{
		passwords:           passwords,
		platform:            platform,
		bootstrapTx:         bootstrapTx,
		rejectionAuditTx:    rejectionAuditTx,
		abuseProtection:     abuseProtection,
		rateLimitRetryAfter: rateLimitRetryAfter,
	}
}

// Initialized reports whether the platform has already been bootstrapped
// — backs GET /v1/platform/status. Deliberately a plain, non-locking
// read: it must return immediately even while a bootstrap attempt holds
// the row lock inside its own transaction.
func (s *BootstrapService) Initialized(ctx context.Context) (bool, error) {
	status, err := s.platform.Status(ctx)
	if err != nil {
		return false, err
	}
	return status == entity.PlatformInitialized, nil
}

type BootstrapInput struct {
	Username  string
	Email     string
	Password  string
	IPAddress string
}

// Bootstrap creates the platform's first administrator.
//
// The password is hashed before the transaction opens — Argon2id is
// supposed to be expensive, and holding a transaction (and the row lock
// below) open for that duration would serialize every concurrent
// bootstrap attempt behind one caller's hashing time for no consistency
// benefit; nothing inside the transaction depends on how the hash was
// computed, only on its final value. This mirrors UserService.Register's
// identical reasoning exactly.
//
// Everything else happens inside one transaction: LockForBootstrap takes
// a row lock on the platform_bootstrap singleton row (see that method's
// doc comment for why this, not a UNIQUE constraint on the not-yet-created
// user, is what actually makes "only one administrator, ever" true under
// concurrent requests — a second concurrent call blocks here until the
// first transaction commits or rolls back, then re-reads the now-committed
// status itself). If the platform turns out to already be initialized,
// the transaction returns ErrAlreadyInitialized and rolls back with
// nothing written. Otherwise: attach to the first existing organization
// if a deployment already provisioned one, or create a default one;
// create the administrator user (identical password hashing to every
// other account this codebase creates); grant it platformAdminRoleID
// (reusing UserRepository.GrantRole — no new role-assignment code); mark
// the platform initialized; append a "platform.initialized" audit event.
// All of it commits together or none of it does.
func (s *BootstrapService) Bootstrap(ctx context.Context, in BootstrapInput) (*entity.User, error) {
	rateLimitDims := ratelimit.Dimensions{IP: in.IPAddress}
	if decision, _ := s.abuseProtection.Check(ctx, ratelimit.OperationBootstrap, rateLimitDims); !decision.Allowed {
		return nil, RateLimitedError{RetryAfter: s.rateLimitRetryAfter}
	}

	hash, err := s.passwords.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	algo := passwordAlgoArgon2id
	username := in.Username
	email := util.NormalizeEmail(in.Email)

	var createdUser *entity.User

	txErr := s.bootstrapTx(ctx, func(
		platform repository.PlatformBootstrapRepository,
		orgs repository.OrganizationRepository,
		users repository.UserRepository,
		audit repository.AuditLogRepository,
	) error {
		status, err := platform.LockForBootstrap(ctx)
		if err != nil {
			return err
		}
		if status != entity.PlatformUninitialized {
			return ErrAlreadyInitialized
		}
		if err := platform.MarkInitializing(ctx); err != nil {
			return err
		}

		orgID, found, err := platform.FirstOrganizationID(ctx)
		if err != nil {
			return err
		}
		if !found {
			org := &entity.Organization{
				Name:   defaultOrganizationName,
				Slug:   defaultOrganizationSlug,
				Status: entity.OrgStatusActive,
			}
			if err := orgs.Create(ctx, org); err != nil {
				return err
			}
			orgID = org.ID
		}

		user := &entity.User{
			OrganizationID: orgID,
			Email:          email,
			Username:       &username,
			PasswordHash:   &hash,
			PasswordAlgo:   &algo,
			Status:         entity.UserStatusActive,
		}
		if err := users.Create(ctx, user); err != nil {
			return err
		}

		if err := users.GrantRole(ctx, &entity.UserRole{
			UserID: user.ID,
			RoleID: platformAdminRoleID,
		}); err != nil {
			return err
		}

		if err := platform.MarkInitialized(ctx, user.ID); err != nil {
			return err
		}

		// Metadata carries only username and (normalized) email — both
		// already visible elsewhere on the user record, mirroring
		// UserService.Register's identical audit entry exactly. There is
		// no path from in.Password or hash into this map, and there must
		// never be one.
		entry := &entity.AuditLogEntry{
			OrganizationID: &orgID,
			ActorType:      entity.AuditActorUser,
			ActorID:        &user.ID,
			Action:         "platform.initialized",
			ResourceType:   strPtr("platform"),
			ResourceID:     strPtr("platform"),
			Result:         entity.AuditResultSuccess,
			IPAddress:      strPtr(in.IPAddress),
			Metadata: map[string]any{
				"username": username,
				"email":    email,
			},
		}
		if err := audit.Append(ctx, entry); err != nil {
			return err
		}

		createdUser = user
		return nil
	})

	if txErr != nil {
		s.abuseProtection.RecordFailure(ctx, ratelimit.OperationBootstrap, rateLimitDims) //nolint:errcheck // best-effort, see AuthAbuseProtection's doc comment
		if errors.Is(txErr, ErrAlreadyInitialized) {
			s.recordRejection(ctx, in)
		}
		return nil, txErr
	}
	if err := s.abuseProtection.RecordSuccess(ctx, ratelimit.OperationBootstrap, rateLimitDims); err != nil {
		logging.FromContext(ctx).Error("failed to reset abuse-protection counters after successful bootstrap", zap.Error(err))
	}

	logging.FromContext(ctx).Info("platform initialized", zap.String("user_id", createdUser.ID))
	return createdUser, nil
}

// recordRejection is best-effort, matching every other audit write in
// this codebase that happens outside the operation's own success/failure
// decision (see AuthService.recordLoginAudit): a Redis/Postgres problem
// recording telemetry about a rejected bootstrap attempt must never
// surface as the reason a client sees something other than the real 409
// CONFLICT. The attempted email is safe to record here (it is not a
// password or credential) and is genuinely useful forensic signal — who,
// or what, is trying to re-bootstrap an already-initialized platform.
func (s *BootstrapService) recordRejection(ctx context.Context, in BootstrapInput) {
	if s.rejectionAuditTx == nil {
		return
	}
	err := s.rejectionAuditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    entity.AuditActorSystem,
			Action:       "platform.bootstrap_rejected",
			ResourceType: strPtr("platform"),
			ResourceID:   strPtr("platform"),
			Result:       entity.AuditResultDenied,
			IPAddress:    strPtr(in.IPAddress),
			Metadata: map[string]any{
				"attempted_email": util.NormalizeEmail(in.Email),
			},
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record rejected bootstrap attempt", zap.Error(err))
	}
}
