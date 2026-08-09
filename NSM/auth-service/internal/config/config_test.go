package config

import (
	"strings"
	"testing"
)

const validKey = "this-is-a-fake-signing-key-that-is-32+-bytes-long"

func TestLoad_FailsClosedWhenSigningKeyMissing(t *testing.T) {
	// No AUTH_* env vars set: environment defaults to "development", so
	// database.password isn't required — the only expected failure is the
	// signing key, which (by design) has no default at all.
	_, err := Load()
	if err == nil {
		t.Fatal("Load() with no JWT signing key set = nil error, want a validation failure")
	}
	if !strings.Contains(err.Error(), "jwt.signing_key") {
		t.Errorf("Load() error = %q, want it to mention jwt.signing_key", err)
	}
}

func TestLoad_EnvironmentVariablesOverrideDefaults(t *testing.T) {
	t.Setenv("AUTH_JWT_SIGNING_KEY", validKey)
	t.Setenv("AUTH_DATABASE_PASSWORD", "s3cret")
	t.Setenv("AUTH_SERVER_HTTP_ADDR", ":9090")
	t.Setenv("AUTH_SERVER_ALLOWED_ORIGINS", "https://a.example.com,https://b.example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	if cfg.Server.HTTPAddr != ":9090" {
		t.Errorf("Server.HTTPAddr = %q, want %q (env override)", cfg.Server.HTTPAddr, ":9090")
	}
	want := []string{"https://a.example.com", "https://b.example.com"}
	if len(cfg.Server.AllowedOrigins) != len(want) || cfg.Server.AllowedOrigins[0] != want[0] || cfg.Server.AllowedOrigins[1] != want[1] {
		t.Errorf("Server.AllowedOrigins = %v, want %v (comma-separated env var split via StringToSliceHookFunc)", cfg.Server.AllowedOrigins, want)
	}
	// Untouched by any env var: still whatever setDefaults put there.
	if cfg.JWT.AccessTokenTTL.String() != "15m0s" {
		t.Errorf("JWT.AccessTokenTTL = %v, want the 15m default to survive when no env var overrides it", cfg.JWT.AccessTokenTTL)
	}
}

func TestLoad_ProductionRequiresDatabasePassword(t *testing.T) {
	t.Setenv("AUTH_JWT_SIGNING_KEY", validKey)
	t.Setenv("AUTH_ENVIRONMENT", "production")
	// Deliberately not setting AUTH_DATABASE_PASSWORD.

	_, err := Load()
	if err == nil {
		t.Fatal("Load() in production with no database.password = nil error, want a validation failure")
	}
	if !strings.Contains(err.Error(), "database.password") {
		t.Errorf("Load() error = %q, want it to mention database.password", err)
	}
	// A valid signing key was set above; if it still shows up as invalid
	// here, AUTH_JWT_SIGNING_KEY silently failed to reach Viper at all —
	// exactly the BindEnv regression this assertion exists to catch.
	if strings.Contains(err.Error(), "jwt.signing_key") {
		t.Errorf("Load() error = %q, unexpectedly also flags jwt.signing_key even though a valid one was set via env", err)
	}
}

func TestDatabaseConfig_DSN(t *testing.T) {
	t.Run("prefers URL when set", func(t *testing.T) {
		d := DatabaseConfig{URL: "postgres://explicit-dsn"}
		if got := d.DSN(); got != d.URL {
			t.Errorf("DSN() = %q, want the URL verbatim %q", got, d.URL)
		}
	})

	t.Run("composes from parts otherwise", func(t *testing.T) {
		d := DatabaseConfig{Host: "db.internal", Port: 5432, User: "svc", Password: "pw", Name: "authdb", SSLMode: "require"}
		want := "postgres://svc:pw@db.internal:5432/authdb?sslmode=require"
		if got := d.DSN(); got != want {
			t.Errorf("DSN() = %q, want %q", got, want)
		}
	})
}
