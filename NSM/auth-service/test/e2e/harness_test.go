//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/config"
	"github.com/acme/auth-service/internal/database"
	httphandler "github.com/acme/auth-service/internal/handler/http"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/security"
	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// e2eOrgID is the organization test/fixtures/organizations.sql guarantees
// exists — the same hardcoded ID test/integration's own tests already
// depend on via users.organization_id's FK.
const e2eOrgID = "00000000-0000-4000-8000-000000000001"

// e2eEnv is everything a scenario test needs: a real HTTP server in front
// of the real router, the real Postgres handle to verify persistence
// directly, and the real token verifiers so a test can validate a token
// the same way the running service itself would, without disabling or
// bypassing signature checking.
type e2eEnv struct {
	BaseURL   string
	DB        *sql.DB
	TokenAuth *util.JWTSigner // verifies POST /v1/auth/login's access tokens (old HS256 stack)
}

// newE2EServer wires the exact same dependency graph cmd/server/main.go
// constructs in production — real Postgres repositories, real Argon2id
// password hashing, a real (freshly generated, never persisted) Ed25519
// signing key loaded through the real security.LoadSigningKeySet, and the
// real httphandler.NewRouter — behind httptest.NewServer. Every request a
// test sends travels client -> real listener -> real router -> real
// middleware -> real handler -> real service -> real Postgres; nothing in
// that chain is stubbed or called directly.
//
// AbuseProtection is ratelimit.NoopAuthAbuseProtection{} — not a test
// double, but the identical concrete type cmd/server/main.go itself
// constructs whenever cfg.RateLimit.Enabled is false. This scenario
// exercises registration, login, and protected-route/middleware wiring,
// none of which involve rate-limiting; the Redis-backed dimension belongs
// to its own later scenario, wired to a real Redis instead.
func newE2EServer(t *testing.T) *e2eEnv {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; see docker/docker-compose.yml for a local Postgres, then run with -tags=e2e")
	}

	db, err := database.NewPostgresPool(context.Background(), config.DatabaseConfig{
		URL:             dsn,
		MaxOpenConns:    5,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { db.Close() })

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

	// The old HS256 signer POST /v1/auth/login actually mints tokens with
	// (see AuthService.issueSession) — a fresh, random-enough key for this
	// process only, never a real secret.
	tokenSigner := util.NewJWTSigner("e2e-test-only-hs256-key-32-bytes-min!!", 15*time.Minute)
	passwordSvc := security.NewPasswordService(security.DefaultParams)

	signingKeys, err := security.LoadSigningKeySet("e2e-test-key-1", generateEd25519PEM(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	accessTokens := security.NewTokenService(signingKeys, "auth-service", 15*time.Minute)

	var abuseProtection ratelimit.AuthAbuseProtection = ratelimit.NoopAuthAbuseProtection{}

	authSvc := service.NewAuthService(service.AuthServiceDeps{
		Users:               userRepo,
		Sessions:            sessionRepo,
		RefreshTokens:       refreshTokenRepo,
		LoginHistory:        loginHistoryRepo,
		Tokens:              tokenSigner,
		Passwords:           passwordSvc,
		RefreshTTL:          30 * 24 * time.Hour,
		AuditTx:             loginAuditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: 60 * time.Second,
	})
	userSvc := service.NewUserService(userRepo, passwordSvc, registerTx)
	sessionSvc := service.NewSessionService(sessionRepo)
	refreshTokenSvc := service.NewRefreshTokenService(service.RefreshTokenServiceDeps{
		RefreshTokens:       refreshTokenRepo,
		Sessions:            sessionSvc,
		Tokens:              accessTokens,
		AccessTokenAudience: "auth-service",
		AccessTokenTTL:      15 * time.Minute,
		RefreshTTL:          7 * 24 * time.Hour,
		AuditTx:             loginAuditTx,
		AbuseProtection:     abuseProtection,
		RateLimitRetryAfter: 60 * time.Second,
	})
	logoutSvc := service.NewLogoutService(service.LogoutServiceDeps{
		Sessions: sessionSvc,
		AuditTx:  loginAuditTx,
	})

	router := httphandler.NewRouter(httphandler.RouterDeps{
		AuthService:         authSvc,
		UserService:         userSvc,
		RefreshTokenService: refreshTokenSvc,
		LogoutService:       logoutSvc,
		TokenAuth:           tokenSigner,
		AccessTokens:        accessTokens,
		AccessTokenAudience: "auth-service",
		AllowedOrigins:      nil,
		Logger:              zap.NewNop(), // never print request/response logs (may carry tokens) to test output
	})

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &e2eEnv{BaseURL: srv.URL, DB: db, TokenAuth: tokenSigner}
}

// generateEd25519PEM returns a freshly generated (never persisted, never
// logged) PKCS#8 PEM-encoded Ed25519 private key — the same
// crypto/rand -> x509.MarshalPKCS8PrivateKey -> pem.EncodeToMemory pattern
// used throughout this codebase's own tests (see e.g.
// internal/security/keys_test.go) and by cmd/devkeygen for local
// development. This is not a second signing-key implementation: it calls
// the identical security.LoadSigningKeySet production code the real
// server uses, just fed inline PEM instead of a file path — exactly the
// "PrivateKeyPEM" input path AccessTokenConfig already documents.
func generateEd25519PEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}
