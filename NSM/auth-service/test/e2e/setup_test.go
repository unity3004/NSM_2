//go:build e2e

// Package e2e contains black-box HTTP tests that exercise the real
// http.Server-equivalent stack — httptest.NewServer wrapping exactly the
// http.Handler httphandler.NewRouter builds for cmd/server/main.go — against
// real PostgreSQL (and, when rate limiting is enabled, real Redis). No
// handler, service, or repository is ever called directly from these tests;
// every assertion is made against an HTTP response that traveled through
// the real router and real middleware chain, the same way a genuine client
// would reach this API.
//
// Run with the local stack up (see ../../docker/docker-compose.yml) and the
// same AUTH_* environment variables docker-compose's app service and
// ../../configs/.env.example already document:
//
//	go test -tags=e2e ./test/e2e/...
//
// See README.md in this directory for the full command and what each
// variable is for.
package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/database"
	httphandler "github.com/acme/auth-service/internal/handler/http"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/ratelimit"
	redisclient "github.com/acme/auth-service/internal/redis"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// fixtureOrgID is the organization test/fixtures/organizations.sql inserts —
// the same row every test/integration test's hardcoded organization ID
// already depends on via users.organization_id's FK. Reusing it here (rather
// than inventing a second fixture) is "use the existing test
// infrastructure," not a new database abstraction.
const fixtureOrgID = "00000000-0000-4000-8000-000000000001"

// e2eEnv is one fully-wired instance of the real application, minus only
// the parts that are specific to running as a standalone OS process
// (http.Server.ListenAndServe, signal handling) — everything that decides
// request behavior (router, middleware, services, repositories) is built
// exactly as cmd/server/main.go builds it, from the same config.Load().
type e2eEnv struct {
	Server    *httptest.Server
	DB        *sql.DB
	Tokens    *util.JWTSigner           // the exact signer AuthService.Login signs access tokens with
	Passwords *security.PasswordService // the exact service UserService/AuthService hash and verify passwords with
	// AccessTokens is the exact Ed25519 security.TokenService instance
	// RefreshTokenService.Refresh mints POST /v1/auth/refresh's access
	// token with — needed so an E2E test can verify that token via the
	// application's own real verification mechanism (ValidateAccessToken)
	// without going through a live HTTP round trip a second time.
	AccessTokens        *security.TokenService
	AccessTokenAudience string
}

// newE2EEnv builds an e2eEnv or fails the calling test outright.
//
// The single skip guard is AUTH_JWT_SIGNING_KEY — config.JWTConfig.SigningKey
// has no default (see config.go) precisely so a forgotten deployment can
// never silently run with a guessable key, which doubles as this suite's
// "has anyone actually configured the local stack for e2e" signal, the same
// role DATABASE_URL/REDIS_ADDR play in test/integration. Once that signal is
// present, every subsequent failure (bad config, unreachable Postgres,
// unreachable Redis when rate limiting is enabled, a missing signing key
// file) is a hard t.Fatalf — never a skip — because at that point the
// environment has declared intent to actually run this suite.
func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()

	if os.Getenv("AUTH_JWT_SIGNING_KEY") == "" {
		t.Skip("AUTH_JWT_SIGNING_KEY not set; bring up the local stack (docker compose -f docker/docker-compose.yml up postgres redis) " +
			"and export the AUTH_* variables from configs/.env.example, then re-run: go test -tags=e2e ./test/e2e/...")
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("newE2EEnv: config.Load: %v (this environment set AUTH_JWT_SIGNING_KEY but is missing other required AUTH_* configuration — see configs/.env.example)", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := database.NewPostgresPool(ctx, cfg.Database)
	if err != nil {
		t.Fatalf("newE2EEnv: connect to Postgres: %v (is docker/docker-compose.yml's postgres service up and migrated?)", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := loadFixtures(ctx, db); err != nil {
		t.Fatalf("newE2EEnv: load fixtures: %v", err)
	}

	userRepo := postgres.NewUserRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(db)
	loginHistoryRepo := postgres.NewLoginHistoryRepository(db)

	registerTx := func(ctx context.Context, fn func(repository.UserRepository, repository.AuditLogRepository) error) error {
		return database.WithTx(ctx, db, func(tx *sql.Tx) error {
			return fn(postgres.NewUserRepository(tx), postgres.NewAuditLogRepository(tx))
		})
	}
	loginAuditTx := func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return database.WithTx(ctx, db, func(tx *sql.Tx) error {
			return fn(postgres.NewAuditLogRepository(tx))
		})
	}
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
	platformStatusRepo := postgres.NewPlatformBootstrapRepository(db)

	tokenSigner := util.NewJWTSigner(cfg.JWT.SigningKey, cfg.JWT.AccessTokenTTL)
	passwordSvc := security.NewPasswordService(security.DefaultParams)

	signingKeys, err := security.LoadSigningKeySet(cfg.AccessToken.KeyID, cfg.AccessToken.PrivateKeyPEM, cfg.AccessToken.PrivateKeyPath)
	if err != nil {
		t.Fatalf("newE2EEnv: load access-token signing key: %v (see configs/.env.example — AUTH_ACCESS_TOKEN_PRIVATE_KEY_PATH, generate one with: go run ./cmd/devkeygen)", err)
	}
	accessTokens := security.NewTokenService(signingKeys, cfg.AccessToken.Issuer, cfg.AccessToken.TTL)

	var abuseProtection ratelimit.AuthAbuseProtection = ratelimit.NoopAuthAbuseProtection{}
	if cfg.RateLimit.Enabled {
		redisClient, err := redisclient.NewClient(ctx, cfg.Redis)
		if err != nil {
			t.Fatalf("newE2EEnv: connect to Redis: %v (rate_limit.enabled is true, the same default production uses, so Redis is required — "+
				"either bring up docker/docker-compose.yml's redis service or set AUTH_RATE_LIMIT_ENABLED=false)", err)
		}
		t.Cleanup(func() { redisClient.Close() })
		abuseProtection = ratelimit.NewRedisAuthAbuseProtection(redisClient, ratelimit.Config{
			FailClosed: cfg.RateLimit.FailClosed,
			Operations: map[string]ratelimit.OperationPolicy{
				ratelimit.OperationLogin: {
					IP:      &ratelimit.DimensionPolicy{Window: cfg.RateLimit.Login.IPWindow, Limit: cfg.RateLimit.Login.IPLimit, BlockDuration: cfg.RateLimit.Login.BlockDuration},
					Account: &ratelimit.DimensionPolicy{Window: cfg.RateLimit.Login.AccountWindow, Limit: cfg.RateLimit.Login.AccountLimit, BlockDuration: cfg.RateLimit.Login.BlockDuration},
					Pair:    &ratelimit.DimensionPolicy{Window: cfg.RateLimit.Login.PairWindow, Limit: cfg.RateLimit.Login.PairLimit, BlockDuration: cfg.RateLimit.Login.BlockDuration},
				},
				ratelimit.OperationRefresh: {
					IP: &ratelimit.DimensionPolicy{Window: cfg.RateLimit.Refresh.IPWindow, Limit: cfg.RateLimit.Refresh.IPLimit, BlockDuration: cfg.RateLimit.Refresh.BlockDuration},
				},
				ratelimit.OperationBootstrap: {
					IP: &ratelimit.DimensionPolicy{Window: cfg.RateLimit.Bootstrap.IPWindow, Limit: cfg.RateLimit.Bootstrap.IPLimit, BlockDuration: cfg.RateLimit.Bootstrap.BlockDuration},
				},
			},
		})
	}

	logger, err := logging.New(cfg.Log.Level, cfg.Log.Format, cfg.Environment, "auth-service-e2e")
	if err != nil {
		t.Fatalf("newE2EEnv: build logger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Sync() })

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
	userSvc := service.NewUserService(userRepo, passwordSvc, registerTx)
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

	router := httphandler.NewRouter(httphandler.RouterDeps{
		AuthService:         authSvc,
		UserService:         userSvc,
		RefreshTokenService: refreshTokenSvc,
		LogoutService:       logoutSvc,
		BootstrapService:    bootstrapSvc,
		TokenAuth:           tokenSigner,
		AccessTokens:        accessTokens,
		AccessTokenAudience: cfg.AccessToken.DefaultAudience,
		AllowedOrigins:      cfg.Server.AllowedOrigins,
		Logger:              logger,
	})

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &e2eEnv{
		Server:              srv,
		DB:                  db,
		Tokens:              tokenSigner,
		Passwords:           passwordSvc,
		AccessTokens:        accessTokens,
		AccessTokenAudience: cfg.AccessToken.DefaultAudience,
	}
}

// loadFixtures is test/integration/main_test.go's loadFixtures, duplicated
// rather than imported: test/integration is package integration (behind its
// own build tag) and exports nothing test/e2e could import without pulling
// that whole package (and its tag) in as a dependency. Both copies apply the
// same idempotent *.sql files under test/fixtures, so they can never
// disagree about what a "migrated database with fixtures" contains.
func loadFixtures(ctx context.Context, db *sql.DB) error {
	const dir = "../fixtures"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if _, err := db.ExecContext(ctx, string(contents)); err != nil {
			return fmt.Errorf("exec %s: %w", path, err)
		}
	}
	return nil
}
