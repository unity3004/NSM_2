package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

const validKey = "this-is-a-fake-signing-key-that-is-32+-bytes-long"

// generateTestEd25519PrivateKeyPEM returns a freshly generated (never
// persisted anywhere, never reused across test runs) PKCS#8 PEM-encoded
// Ed25519 private key — a test fixture, not a "private development key"
// committed to the repository, the same distinction internal/security's
// own tests already draw for the same reason.
func generateTestEd25519PrivateKeyPEM(t *testing.T) string {
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

// setValidAccessTokenEnv sets the env vars Validate now hard-requires for
// access_token.key_id/private_key_pem (Milestone 5B: cmd/server/main.go
// now actually constructs a security.TokenService from them) — every
// Load() test that expects success, or expects a *different* field to be
// the one that fails, needs these set so this requirement doesn't mask
// what the test is actually checking.
func setValidAccessTokenEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_ACCESS_TOKEN_KEY_ID", "test-key-1")
	t.Setenv("AUTH_ACCESS_TOKEN_PRIVATE_KEY_PEM", generateTestEd25519PrivateKeyPEM(t))
}

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
	setValidAccessTokenEnv(t)
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
	setValidAccessTokenEnv(t)
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

// TestLoad_PostgresProvisionerEnvVarsAreBound is a regression test for a
// real gap the Dynamic Secrets & Lease Engine phase found: none of
// postgres_provisioner.{host,port,user,password,name} had a default, a
// config-file entry, or an explicit BindEnv call — which meant, despite
// looking identical to every other secret-shaped field in this file
// (database.password, secrets.dev_master_key, ...), Viper's AutomaticEnv
// silently never read AUTH_POSTGRES_PROVISIONER_* for any of them. An
// operator could set postgres_provisioner.enabled=true and every one of
// these variables and still get an empty Host/User/Password/Name back —
// exactly the "operator sets everything, feature silently doesn't work"
// failure mode the surrounding BindEnv comment block already warns other
// fields in this function against. This test sets every scalar
// connection field via its env var and asserts Load() actually carries
// each one through — role_templates is deliberately not exercised here
// (it has no env-var mechanism at all, by design — an array can't be
// flattened into a single environment variable the way a scalar can; see
// configs/config.yaml's own worked example for how that field is meant
// to be configured instead), so Enabled is left false here purely to
// keep Validate() from also demanding a role_templates entry this test
// isn't about.
func TestLoad_PostgresProvisionerEnvVarsAreBound(t *testing.T) {
	t.Setenv("AUTH_JWT_SIGNING_KEY", validKey)
	t.Setenv("AUTH_DATABASE_PASSWORD", "s3cret")
	setValidAccessTokenEnv(t)
	t.Setenv("AUTH_POSTGRES_PROVISIONER_HOST", "provisioner.internal")
	t.Setenv("AUTH_POSTGRES_PROVISIONER_PORT", "5433")
	t.Setenv("AUTH_POSTGRES_PROVISIONER_USER", "vault_provisioner")
	t.Setenv("AUTH_POSTGRES_PROVISIONER_PASSWORD", "provisioner-secret")
	t.Setenv("AUTH_POSTGRES_PROVISIONER_NAME", "authdb")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}

	p := cfg.PostgresProvisioner
	if p.Host != "provisioner.internal" {
		t.Errorf("PostgresProvisioner.Host = %q, want %q (AUTH_POSTGRES_PROVISIONER_HOST)", p.Host, "provisioner.internal")
	}
	if p.Port != 5433 {
		t.Errorf("PostgresProvisioner.Port = %d, want 5433 (AUTH_POSTGRES_PROVISIONER_PORT)", p.Port)
	}
	if p.User != "vault_provisioner" {
		t.Errorf("PostgresProvisioner.User = %q, want %q (AUTH_POSTGRES_PROVISIONER_USER)", p.User, "vault_provisioner")
	}
	if p.Password != "provisioner-secret" {
		t.Errorf("PostgresProvisioner.Password = %q, want %q (AUTH_POSTGRES_PROVISIONER_PASSWORD) — this is the field that was silently empty before the BindEnv fix", p.Password, "provisioner-secret")
	}
	if p.Name != "authdb" {
		t.Errorf("PostgresProvisioner.Name = %q, want %q (AUTH_POSTGRES_PROVISIONER_NAME)", p.Name, "authdb")
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
