// Command server is the single entrypoint binary for the authentication
// service. It only wires dependencies together — every real decision (what a
// login does, how a token is validated) lives in internal/, never here.
package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/database"
	httphandler "github.com/acme/auth-service/internal/handler/http"
	"github.com/acme/auth-service/internal/leasing"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/ratelimit"
	redisclient "github.com/acme/auth-service/internal/redis"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/secrets"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

func main() {
	// A minimal, hardcoded-format bootstrap logger — the one deliberate
	// exception to "configuration, not constants" in this whole service,
	// because it exists only to report "config.Load failed" before any
	// configuration (including the desired log level/format) exists to
	// read. It is used for exactly the lines between here and the first
	// successful Load(), and never again.
	bootstrap, _ := zap.NewProduction()
	defer bootstrap.Sync() //nolint:errcheck

	cfg, err := config.Load()
	if err != nil {
		bootstrap.Error("failed to load configuration", zap.Error(err))
		os.Exit(1)
	}
	// Sprint 4 Task 4: must happen before the router (and therefore any
	// request) can possibly run — see util.SetTrustedProxies' own doc
	// comment for why this is a package-level value configured once here
	// rather than threaded through every handler.
	util.SetTrustedProxies(cfg.Server.TrustedProxies)

	logger, err := logging.New(cfg.Log.Level, cfg.Log.Format, cfg.Environment, "auth-service")
	if err != nil {
		bootstrap.Error("failed to build logger", zap.Error(err))
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck
	// zap.L() is what logging.FromContext falls back to for any log call
	// made outside a request — a background job, or this function itself
	// from here on — so nothing accidentally reverts to the bootstrap
	// logger's hardcoded format once the real one is available.
	zap.ReplaceGlobals(logger)

	// Safe to log in full: Config.MarshalLogObject redacts every secret
	// field — see internal/config/log_value.go. Logging the *resolved*
	// config (after env vars and config.yaml have both been applied) is
	// what makes "why is this instance talking to the wrong database" a
	// one-line answer instead of a guessing game.
	logger.Info("configuration loaded", zap.Object("config", cfg))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		logger.Error("failed to connect to database", zap.Error(err))
		os.Exit(1)
	}
	defer db.Close()

	// --- repositories (adapters implementing internal/repository's ports) ---
	userRepo := postgres.NewUserRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(db)
	loginHistoryRepo := postgres.NewLoginHistoryRepository(db)
	roleRepo := postgres.NewRoleRepository(db)
	permissionRepo := postgres.NewPermissionRepository(db)
	rbacRepo := postgres.NewRBACRepository(db)
	// serviceAccountRepo/apiKeyRepo (Sprint 5 Task 1) back
	// ServiceAccountService — the machine-identity counterpart to
	// userRepo above.
	serviceAccountRepo := postgres.NewServiceAccountRepository(db)
	apiKeyRepo := postgres.NewAPIKeyRepository(db)

	// registerTx is the one place outside internal/repository/postgres
	// itself that constructs a Postgres repository directly — exactly the
	// wiring point service.RegistrationTxFunc's doc comment describes:
	// database.WithTx opens the transaction, and the closure hands
	// UserService.Register a UserRepository/AuditLogRepository pair
	// scoped to it, so the users INSERT and the audit_logs INSERT commit
	// or roll back together.
	registerTx := func(ctx context.Context, fn func(repository.UserRepository, repository.AuditLogRepository) error) error {
		return database.WithTx(ctx, db, func(tx *sql.Tx) error {
			return fn(postgres.NewUserRepository(tx), postgres.NewAuditLogRepository(tx))
		})
	}

	// loginAuditTx is service.AuthServiceDeps.AuditTx's wiring point — the
	// single-repository sibling of registerTx above, for the same reason:
	// postgres.NewAuditLogRepository's hash-chain lock only serializes
	// correctly when it runs against a *sql.Tx, never a bare *sql.DB.
	loginAuditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return database.WithTx(ctx, db, func(tx *sql.Tx) error {
			return fn(postgres.NewAuditLogRepository(tx))
		})
	}

	// bootstrapTx is service.BootstrapTxFunc's wiring point — every
	// repository BootstrapService.Bootstrap touches (the singleton
	// platform_bootstrap row, an organization, a user, and the audit
	// chain) constructed against the same *sql.Tx, so
	// PlatformBootstrapRepository.LockForBootstrap's row lock actually
	// serializes concurrent callers the way its doc comment describes —
	// exactly the same requirement registerTx and loginAuditTx above
	// already exist to satisfy for their own repositories.
	bootstrapTx := func(ctx context.Context, fn func(repository.PlatformBootstrapRepository, repository.OrganizationRepository, repository.UserRepository, repository.AuditLogRepository) error) error {
		return database.WithTx(ctx, db, func(tx *sql.Tx) error {
			return fn(
				postgres.NewPlatformBootstrapRepository(tx),
				postgres.NewOrganizationRepository(tx),
				postgres.NewUserRepository(tx),
				postgres.NewAuditLogRepository(tx),
			)
		})
	}
	// platformStatusRepo is BootstrapService's non-transactional
	// dependency for GET /v1/platform/status — see
	// BootstrapService.Initialized's doc comment for why that read must
	// never go through bootstrapTx (it would block behind a concurrent
	// bootstrap attempt's row lock).
	platformStatusRepo := postgres.NewPlatformBootstrapRepository(db)

	// --- shared infrastructure utilities ---
	tokenSigner := util.NewJWTSigner(cfg.JWT.SigningKey, cfg.JWT.AccessTokenTTL)
	// One PasswordService instance, shared by both services below, so
	// UserService.CreateUser (Hash) and AuthService.Login (Verify) are
	// always talking about the same Argon2id parameters — see
	// AuthServiceDeps.Passwords' doc comment.
	passwordSvc := security.NewPasswordService(security.DefaultParams)

	// signingKeys/accessTokens back security.TokenService (Milestone 5A),
	// now actually constructed for the first time — see
	// AccessTokenConfig's doc comment on why Config.Validate only started
	// hard-requiring these fields once something depended on them for
	// real.
	signingKeys, err := security.LoadSigningKeySet(cfg.AccessToken.KeyID, cfg.AccessToken.PrivateKeyPEM, cfg.AccessToken.PrivateKeyPath)
	if err != nil {
		logger.Error("failed to load access token signing key", zap.Error(err))
		os.Exit(1)
	}
	accessTokens := security.NewTokenService(signingKeys, cfg.AccessToken.Issuer, cfg.AccessToken.TTL)

	// abuseProtection (Milestone 6C) defaults to allowing everything —
	// the posture for a deployment that hasn't turned rate_limit.enabled
	// on yet — and is only replaced with the real Redis-backed
	// implementation when it is. AuthService/RefreshTokenService always
	// hold a non-nil AuthAbuseProtection either way; see
	// ratelimit.NoopAuthAbuseProtection's own doc comment.
	var abuseProtection ratelimit.AuthAbuseProtection = ratelimit.NoopAuthAbuseProtection{}
	// apiRateLimiter (Sprint 4 Task 4) is the general request throttle —
	// see internal/ratelimit's own package doc comment for why this is a
	// distinct component from abuseProtection above, not a replacement
	// for it. Deliberately constructed from the *same* redisClient
	// connection abuseProtection uses below, not a second one — this
	// task's own "do not create a second Redis client unnecessarily"
	// instruction — since both are Redis-backed rate limiters serving
	// the same process against the same Redis deployment.
	var apiRateLimiter ratelimit.APIRateLimiter = ratelimit.NoopAPIRateLimiter{}
	if cfg.RateLimit.Enabled {
		redisClient, err := redisclient.NewClient(ctx, cfg.Redis)
		if err != nil {
			logger.Error("failed to connect to redis", zap.Error(err))
			os.Exit(1)
		}
		defer redisClient.Close()

		apiRateLimiter = ratelimit.NewRedisAPIRateLimiter(redisClient, ratelimit.APIRateLimiterConfig{
			Categories: map[string]ratelimit.CategoryConfig{
				"secrets-read": {
					User:           windowPolicy(cfg.RateLimit.API.SecretsRead.UserWindow, cfg.RateLimit.API.SecretsRead.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.SecretsRead.ServiceAccountWindow, cfg.RateLimit.API.SecretsRead.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.SecretsRead.FailOpen,
				},
				"secrets-write": {
					User:           windowPolicy(cfg.RateLimit.API.SecretsWrite.UserWindow, cfg.RateLimit.API.SecretsWrite.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.SecretsWrite.ServiceAccountWindow, cfg.RateLimit.API.SecretsWrite.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.SecretsWrite.FailOpen,
				},
				"policy-admin": {
					User:           windowPolicy(cfg.RateLimit.API.PolicyAdmin.UserWindow, cfg.RateLimit.API.PolicyAdmin.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.PolicyAdmin.ServiceAccountWindow, cfg.RateLimit.API.PolicyAdmin.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.PolicyAdmin.FailOpen,
				},
				"user-admin": {
					User:           windowPolicy(cfg.RateLimit.API.UserAdmin.UserWindow, cfg.RateLimit.API.UserAdmin.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.UserAdmin.ServiceAccountWindow, cfg.RateLimit.API.UserAdmin.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.UserAdmin.FailOpen,
				},
				"audit-read": {
					User:           windowPolicy(cfg.RateLimit.API.AuditRead.UserWindow, cfg.RateLimit.API.AuditRead.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.AuditRead.ServiceAccountWindow, cfg.RateLimit.API.AuditRead.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.AuditRead.FailOpen,
				},
				"auth-register": {
					IP:       windowPolicy(cfg.RateLimit.API.AuthRegister.IPWindow, cfg.RateLimit.API.AuthRegister.IPLimit),
					FailOpen: cfg.RateLimit.API.AuthRegister.FailOpen,
				},
				"auth-logout": {
					User:           windowPolicy(cfg.RateLimit.API.AuthLogout.UserWindow, cfg.RateLimit.API.AuthLogout.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.AuthLogout.ServiceAccountWindow, cfg.RateLimit.API.AuthLogout.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.AuthLogout.FailOpen,
				},
				"service-account-admin": {
					User:           windowPolicy(cfg.RateLimit.API.ServiceAccountAdmin.UserWindow, cfg.RateLimit.API.ServiceAccountAdmin.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.ServiceAccountAdmin.ServiceAccountWindow, cfg.RateLimit.API.ServiceAccountAdmin.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.ServiceAccountAdmin.FailOpen,
				},
				"lease-create": {
					User:           windowPolicy(cfg.RateLimit.API.LeaseCreate.UserWindow, cfg.RateLimit.API.LeaseCreate.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.LeaseCreate.ServiceAccountWindow, cfg.RateLimit.API.LeaseCreate.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.LeaseCreate.FailOpen,
				},
				"lease-read": {
					User:           windowPolicy(cfg.RateLimit.API.LeaseRead.UserWindow, cfg.RateLimit.API.LeaseRead.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.LeaseRead.ServiceAccountWindow, cfg.RateLimit.API.LeaseRead.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.LeaseRead.FailOpen,
				},
				"lease-renew": {
					User:           windowPolicy(cfg.RateLimit.API.LeaseRenew.UserWindow, cfg.RateLimit.API.LeaseRenew.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.LeaseRenew.ServiceAccountWindow, cfg.RateLimit.API.LeaseRenew.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.LeaseRenew.FailOpen,
				},
				"lease-revoke": {
					User:           windowPolicy(cfg.RateLimit.API.LeaseRevoke.UserWindow, cfg.RateLimit.API.LeaseRevoke.UserLimit),
					ServiceAccount: windowPolicy(cfg.RateLimit.API.LeaseRevoke.ServiceAccountWindow, cfg.RateLimit.API.LeaseRevoke.ServiceAccountLimit),
					FailOpen:       cfg.RateLimit.API.LeaseRevoke.FailOpen,
				},
			},
		})

		abuseProtection = ratelimit.NewRedisAuthAbuseProtection(redisClient, ratelimit.Config{
			FailClosed: cfg.RateLimit.FailClosed,
			Operations: map[string]ratelimit.OperationPolicy{
				ratelimit.OperationLogin: {
					IP: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.Login.IPWindow, Limit: cfg.RateLimit.Login.IPLimit, BlockDuration: cfg.RateLimit.Login.BlockDuration,
					},
					Account: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.Login.AccountWindow, Limit: cfg.RateLimit.Login.AccountLimit, BlockDuration: cfg.RateLimit.Login.BlockDuration,
					},
					Pair: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.Login.PairWindow, Limit: cfg.RateLimit.Login.PairLimit, BlockDuration: cfg.RateLimit.Login.BlockDuration,
					},
				},
				// Refresh is deliberately IP-only — see
				// RefreshTokenServiceDeps.AbuseProtection's doc comment.
				ratelimit.OperationRefresh: {
					IP: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.Refresh.IPWindow, Limit: cfg.RateLimit.Refresh.IPLimit, BlockDuration: cfg.RateLimit.Refresh.BlockDuration,
					},
				},
				// Bootstrap is IP-only for the same reason Refresh is —
				// see BootstrapRateLimitConfig's doc comment.
				ratelimit.OperationBootstrap: {
					IP: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.Bootstrap.IPWindow, Limit: cfg.RateLimit.Bootstrap.IPLimit, BlockDuration: cfg.RateLimit.Bootstrap.BlockDuration,
					},
				},
				// Sprint 5 Task 1: machine-credential brute-force
				// protection, the same three-dimension shape Login uses —
				// see ServiceAccountAuthRateLimitConfig's own doc comment.
				ratelimit.OperationServiceAccountAuth: {
					IP: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.ServiceAccountAuth.IPWindow, Limit: cfg.RateLimit.ServiceAccountAuth.IPLimit, BlockDuration: cfg.RateLimit.ServiceAccountAuth.BlockDuration,
					},
					Account: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.ServiceAccountAuth.ServiceAccountWindow, Limit: cfg.RateLimit.ServiceAccountAuth.ServiceAccountLimit, BlockDuration: cfg.RateLimit.ServiceAccountAuth.BlockDuration,
					},
					Pair: &ratelimit.DimensionPolicy{
						Window: cfg.RateLimit.ServiceAccountAuth.PairWindow, Limit: cfg.RateLimit.ServiceAccountAuth.PairLimit, BlockDuration: cfg.RateLimit.ServiceAccountAuth.BlockDuration,
					},
				},
			},
		})
	}

	// --- services (use cases, depend only on repository interfaces) ---
	authSvc := service.NewAuthService(service.AuthServiceDeps{
		Users:               userRepo,
		Sessions:            sessionRepo,
		RefreshTokens:       refreshTokenRepo,
		LoginHistory:        loginHistoryRepo,
		Tokens:              tokenSigner,
		Passwords:           passwordSvc,
		RefreshTTL:          cfg.JWT.RefreshTokenTTL,
		AuditTx:             loginAuditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: cfg.RateLimit.RetryAfter,
	})
	userSvc := service.NewUserService(userRepo, sessionRepo, passwordSvc, registerTx, loginAuditTx)
	sessionSvc := service.NewSessionService(sessionRepo)
	refreshTokenSvc := service.NewRefreshTokenService(service.RefreshTokenServiceDeps{
		RefreshTokens:       refreshTokenRepo,
		Sessions:            sessionSvc,
		Tokens:              accessTokens,
		AccessTokenAudience: cfg.AccessToken.DefaultAudience,
		AccessTokenTTL:      cfg.AccessToken.TTL,
		RefreshTTL:          cfg.RefreshToken.TTL,
		AuditTx:             loginAuditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: cfg.RateLimit.RetryAfter,
	})
	logoutSvc := service.NewLogoutService(service.LogoutServiceDeps{
		Sessions: sessionSvc,
		AuditTx:  loginAuditTx,
	})
	bootstrapSvc := service.NewBootstrapService(
		passwordSvc,
		platformStatusRepo,
		bootstrapTx,
		loginAuditTx,
		abuseProtection,
		cfg.RateLimit.RetryAfter,
	)
	roleSvc := service.NewRoleService(roleRepo, permissionRepo, rbacRepo)
	rbacSvc := service.NewRBACService(rbacRepo)
	// serviceAccountSvc (Sprint 5 Task 1) reuses tokenSigner (the same
	// *util.JWTSigner human login already signs with — see
	// util.Claims.IsServiceAccount's own doc comment on why a shared
	// signer is exactly what lets one middleware.Auth verify both kinds
	// of token) and abuseProtection (the same Redis-backed
	// AuthAbuseProtection instance Login/Refresh/Bootstrap already share —
	// this task's own "reuse the existing Redis infrastructure" instruction,
	// applied to authentication abuse protection the way Sprint 4 Task 4
	// already applied it to general request throttling).
	serviceAccountSvc := service.NewServiceAccountService(
		serviceAccountRepo, apiKeyRepo, tokenSigner, abuseProtection, cfg.RateLimit.RetryAfter, loginAuditTx,
	)
	// AuditService (Sprint 4 Task 3) reads directly off a plain,
	// AuditService (Sprint 4 Task 3) reads directly off a plain,
	// non-transactional repository (unlike loginAuditTx below, which
	// exists for one-Append-inside-a-transaction writes) — List/GetByID
	// need no advisory lock or hash-chain write, only a read, so there's
	// no reason to pay for a transaction here.
	auditSvc := service.NewAuditService(postgres.NewAuditLogRepository(db), rbacSvc, loginAuditTx)

	// secretSvc (Sprint 3 Phase 4) is only constructed when the Secrets
	// Engine's key material is actually configured — see
	// config.SecretsConfig's own doc comment for why Validate doesn't hard
	// -require AUTH_SECRETS_DEV_MASTER_KEY the way it does
	// jwt.signing_key: DevKeyProvider is explicitly development-only
	// (internal/secrets/key_provider.go), and this codebase has no
	// production-grade KeyProvider yet. Leaving it unset is a legitimate,
	// supported "Secrets Engine not enabled for this deployment" state —
	// httphandler.RouterDeps.SecretService tolerates a nil value by simply
	// not registering /v1/secrets* at all (see NewRouter), rather than
	// this binary refusing to start or those routes panicking.
	var secretSvc *service.SecretService
	var secretPolicySvc *service.SecretPolicyService
	var keyRotationSvc *service.KeyRotationService
	// leaseSvc (Sprint 5 Task 2) is constructed alongside secretSvc, under
	// the identical "Secrets Engine enabled" guard — LeaseService reuses
	// secretPolicySvc for path authorization, so there is nothing for it
	// to authorize a lease's resource path against when that isn't
	// configured either.
	var leaseSvc *service.LeaseService
	// devCredentialProvider is the one DynamicCredentialProvider this
	// task registers — see leasing.DevCredentialProvider's own doc
	// comment on why no production provider exists yet. Constructed
	// unconditionally (it needs no configuration at all, unlike
	// DevKeyProvider) but only ever wired into leaseSvc below, when the
	// Secrets Engine itself is enabled.
	devCredentialProvider := leasing.NewDevCredentialProvider()
	if cfg.Secrets.DevMasterKey == "" {
		logger.Warn("AUTH_SECRETS_DEV_MASTER_KEY not set — Secrets Engine disabled, /v1/secrets routes will not be registered")
	} else {
		secretRepo := postgres.NewSecretRepository(db)
		// Sprint 4 Task 2: the path-authorization layer SecretService now
		// requires — see SecretService.authorizeSecretAccess's own doc
		// comment. Wired here, not left nil, in every deployment that has
		// the Secrets Engine enabled at all: deny-by-default only means
		// something if this is actually consulted.
		secretPolicyRepo := postgres.NewSecretPolicyRepository(db)
		secretPolicySvc = service.NewSecretPolicyService(secretPolicyRepo, userRepo, serviceAccountRepo, rbacSvc, loginAuditTx)
		keyProvider, err := secrets.NewDevKeyProvider(cfg.Secrets.DevMasterKeyID, cfg.Secrets.DevMasterKey)
		if err != nil {
			logger.Error("failed to construct secrets key provider", zap.Error(err))
			os.Exit(1)
		}
		// Sprint 4 Task 1: EncryptionService no longer talks to
		// keyProvider directly — KeyManager sits between them (Secret ->
		// Crypto Service -> Key Manager -> Key Provider, per this sprint's
		// objective), adding lifecycle state and rotation on top of the
		// same DevKeyProvider this deployment has always used. This is
		// the only line that changed for EncryptionService to gain that
		// layer: *secrets.KeyManager implements secrets.KeyProvider
		// (same GetCurrentKey/GetKey signatures), so
		// NewEncryptionService's own code is untouched — see
		// secrets.KeyManager's doc comment.
		keyMetadataStore := postgres.NewKeyMetadataStore(db)
		keyManager := secrets.NewKeyManager(keyProvider, keyMetadataStore)
		encryptionSvc := secrets.NewEncryptionService(keyManager)
		// loginAuditTx (constructed above for AuthService/RefreshTokenService/
		// LogoutService/BootstrapService) is reused verbatim — it's already
		// exactly service.AuditTxFunc's shape, and SecretService's own audit
		// writes are best-effort/single-repository the same way every other
		// consumer of this closure's writes already are (see
		// SecretService.recordSecretAudit's doc comment).
		secretSvc = service.NewSecretService(secretRepo, encryptionSvc, rbacSvc, secretPolicySvc, loginAuditTx)

		// leaseSvc (Sprint 5 Task 2): dev-credential is the only
		// DynamicCredentialProvider registered today — see
		// leasing.DevCredentialProvider's own doc comment for why this
		// task deliberately implements no production credential backend.
		// A future provider (Postgres, cloud IAM, etc.) adds a second map
		// entry here, never a change to LeaseService's own code.
		leaseSvc = service.NewLeaseService(service.LeaseServiceDeps{
			Leases:   postgres.NewLeaseRepository(db),
			RBAC:     rbacSvc,
			Policies: secretPolicySvc,
			Providers: map[string]leasing.DynamicCredentialProvider{
				devCredentialProvider.Type(): devCredentialProvider,
			},
			MinTTL:               cfg.Lease.MinTTL,
			DefaultTTL:           cfg.Lease.DefaultTTL,
			MaxTTL:               cfg.Lease.MaxTTL,
			MaxRenewableLifetime: cfg.Lease.MaxRenewableLifetime,
			AuditTx:              loginAuditTx,
		})

		keyRotationSvc = service.NewKeyRotationService(keyManager, secretRepo, loginAuditTx)
		// Explicit at startup, not left to happen lazily on the first
		// /v1/secrets request — see KeyRotationService.EnsureBootstrapped's
		// own doc comment for why: a misconfigured or unreachable key
		// metadata store fails the process here, with a clear log line,
		// instead of surfacing as a confusing first-request error later.
		if _, err := keyRotationSvc.EnsureBootstrapped(context.Background()); err != nil {
			logger.Error("failed to bootstrap the Secrets Engine's key manager", zap.Error(err))
			os.Exit(1)
		}
	}

	// --- delivery: HTTP handlers + router ---
	router := httphandler.NewRouter(httphandler.RouterDeps{
		AuthService:           authSvc,
		UserService:           userSvc,
		RefreshTokenService:   refreshTokenSvc,
		LogoutService:         logoutSvc,
		BootstrapService:      bootstrapSvc,
		RoleService:           roleSvc,
		RBACService:           rbacSvc,
		AuditService:          auditSvc,
		AuditTx:               loginAuditTx,
		SecretService:         secretSvc,
		SecretPolicyService:   secretPolicySvc,
		ServiceAccountService: serviceAccountSvc,
		LeaseService:          leaseSvc,
		RateLimiter:           apiRateLimiter,
		TokenAuth:             tokenSigner,
		AccessTokens:          accessTokens,
		AccessTokenAudience:   cfg.AccessToken.DefaultAudience,
		AllowedOrigins:        cfg.Server.AllowedOrigins,
		Logger:                logger,
	})

	srv := &http.Server{
		Addr:              cfg.Server.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("http server listening", zap.String("addr", cfg.Server.HTTPAddr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server failed", zap.Error(err))
			os.Exit(1)
		}
	}()

	// Best-effort lease-expiry sweep (Sprint 5 Task 2). This is
	// defense-in-depth tidy-up only, never the authorization boundary
	// itself — LeaseService.Get/Renew already check entity.Lease.IsExpired
	// live on every request, so a stalled or entirely-disabled worker
	// never lets an expired lease remain usable, only lets its Status
	// column and DB row go stale until the next sweep or next
	// authorization-time check corrects it (see
	// LeaseService.ExpireOverdue's own doc comment). Runs only when
	// leasing is enabled (leaseSvc != nil, i.e. the Secrets Engine is
	// configured) and CleanupInterval is positive, and stops on the same
	// shutdown signal every other background goroutine in this file
	// stops on.
	if leaseSvc != nil && cfg.Lease.CleanupInterval > 0 {
		go func() {
			ticker := time.NewTicker(cfg.Lease.CleanupInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					n, err := leaseSvc.ExpireOverdue(ctx)
					if err != nil {
						logger.Error("lease expiry sweep failed", zap.Error(err))
						continue
					}
					if n > 0 {
						logger.Info("lease expiry sweep expired overdue leases", zap.Int("count", n))
					}
				}
			}
		}()
	}

	<-ctx.Done()
	logger.Info("shutdown signal received, draining connections")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", zap.Error(err))
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}

// windowPolicy translates one RequestCategoryConfig field pair into a
// *ratelimit.WindowPolicy, or nil when either half is non-positive — the
// "not configured for this identity type" case, matching
// ratelimit.CategoryConfig's own "nil field means this dimension doesn't
// apply" convention. An operator who wants to disable one identity type
// within a category (without disabling the whole category) sets its
// limit to 0 and gets exactly that, rather than an accidental
// always-allow or always-deny policy.
func windowPolicy(window time.Duration, limit int64) *ratelimit.WindowPolicy {
	if window <= 0 || limit <= 0 {
		return nil
	}
	return &ratelimit.WindowPolicy{Window: window, Limit: limit}
}
