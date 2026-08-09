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
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
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

	// --- shared infrastructure utilities ---
	tokenSigner := util.NewJWTSigner(cfg.JWT.SigningKey, cfg.JWT.AccessTokenTTL)
	// One PasswordService instance, shared by both services below, so
	// UserService.CreateUser (Hash) and AuthService.Login (Verify) are
	// always talking about the same Argon2id parameters — see
	// AuthServiceDeps.Passwords' doc comment.
	passwordSvc := security.NewPasswordService(security.DefaultParams)

	// --- services (use cases, depend only on repository interfaces) ---
	authSvc := service.NewAuthService(service.AuthServiceDeps{
		Users:         userRepo,
		Sessions:      sessionRepo,
		RefreshTokens: refreshTokenRepo,
		LoginHistory:  loginHistoryRepo,
		Tokens:        tokenSigner,
		Passwords:     passwordSvc,
		RefreshTTL:    cfg.JWT.RefreshTokenTTL,
		AuditTx:       loginAuditTx,
	})
	userSvc := service.NewUserService(userRepo, passwordSvc, registerTx)

	// --- delivery: HTTP handlers + router ---
	router := httphandler.NewRouter(httphandler.RouterDeps{
		AuthService:    authSvc,
		UserService:    userSvc,
		TokenAuth:      tokenSigner,
		AllowedOrigins: cfg.Server.AllowedOrigins,
		Logger:         logger,
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
