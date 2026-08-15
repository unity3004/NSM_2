// Package config loads runtime configuration through Viper, from — in
// order of precedence, highest first:
//
//  1. Environment variables (AUTH_SERVER_HTTP_ADDR, AUTH_JWT_SIGNING_KEY, ...)
//  2. configs/config.yaml, if present (non-secret operational defaults —
//     see that file's own comment for what belongs there and what never does)
//  3. The SetDefault calls below
//
// This package is code — how to load and validate settings. configs/ is
// data — the actual values. See the package-level doc comment in
// configs/config.yaml for why that split matters, and README.md /
// "Why not hardcode configuration" for the fuller argument this design
// is answering.
package config

import (
	"fmt"
	"strings"
	"time"

	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type Config struct {
	// Environment selects behavior that should differ by deployment —
	// e.g. whether internal/handler/http returns stack traces in error
	// bodies. It is itself configuration, not a hardcoded `if isProd`
	// switch, so a new environment (a "canary" tier, a "loadtest" tier)
	// never requires a code change.
	Environment         string                    `mapstructure:"environment"`
	Server              ServerConfig              `mapstructure:"server"`
	Database            DatabaseConfig            `mapstructure:"database"`
	Redis               RedisConfig               `mapstructure:"redis"`
	JWT                 JWTConfig                 `mapstructure:"jwt"`
	AccessToken         AccessTokenConfig         `mapstructure:"access_token"`
	RefreshToken        RefreshTokenConfig        `mapstructure:"refresh_token"`
	RateLimit           RateLimitConfig           `mapstructure:"rate_limit"`
	Secrets             SecretsConfig             `mapstructure:"secrets"`
	Lease               LeaseConfig               `mapstructure:"lease"`
	PostgresProvisioner PostgresProvisionerConfig `mapstructure:"postgres_provisioner"`
	Log                 LogConfig                 `mapstructure:"log"`
}

type ServerConfig struct {
	HTTPAddr        string        `mapstructure:"http_addr"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	// AllowedOrigins feeds internal/middleware.CORS. A comma-separated
	// AUTH_SERVER_ALLOWED_ORIGINS env var becomes this slice via the
	// StringToSliceHookFunc registered in Load — see the comment there.
	AllowedOrigins []string `mapstructure:"allowed_origins"`
	// TrustedProxies (Sprint 4 Task 4) lists the CIDR ranges of reverse
	// proxies/load balancers this deployment sits behind — see
	// util.ResolveClientIP's own doc comment for exactly how this is
	// used. Empty (the default) means "no trusted proxy": every client-IP
	// resolution ignores X-Forwarded-For/X-Real-IP entirely and uses the
	// TCP peer address only, which is the only safe default for a
	// deployment that hasn't explicitly declared what sits in front of
	// it — trusting either header by default would let any direct client
	// spoof its own rate-limit/audit identity for free.
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

// DatabaseConfig describes the connection Postgres pool internal/database
// opens. URL, if set, wins outright — it exists because most hosting
// platforms (Render, Railway, Heroku-style PaaS) inject one pre-built
// connection string rather than five separate host/port/user fields; the
// component fields below are for everyone else, including local dev.
type DatabaseConfig struct {
	URL             string        `mapstructure:"url"`
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Name            string        `mapstructure:"name"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
}

// DSN returns the connection string internal/database.NewPostgresPool
// should open — URL verbatim if the deployment provided one, otherwise
// composed from the component fields. This is the one place that
// composition happens, so nothing downstream needs to know which style a
// given environment uses.
func (d DatabaseConfig) DSN() string {
	if d.URL != "" {
		return d.URL
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode)
}

// RedisConfig describes the connection internal/redis.NewClient opens —
// backing internal/ratelimit's authentication abuse protection (Milestone
// 6C). Host/Port always have working local-dev defaults (see setDefaults);
// only Password has none, the same secret-gets-no-default rule
// database.password and jwt.signing_key already follow — but unlike that
// database password, an empty Redis password is common and legitimate
// (a private-network Redis with no auth configured), so Validate does not
// require it to be set.
type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	PoolSize     int           `mapstructure:"pool_size"`
}

type JWTConfig struct {
	// SigningKey has no default (see Load) — an empty value must fail
	// startup, never fall back to a value that works "well enough" to not
	// get noticed.
	SigningKey      string        `mapstructure:"signing_key"`
	AccessTokenTTL  time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL time.Duration `mapstructure:"refresh_token_ttl"`
}

// AccessTokenConfig configures security.TokenService (Milestone 5A) — the
// new Ed25519/EdDSA-signed access token issuer, kept deliberately separate
// from JWTConfig above (the existing HS256 implementation util.JWTSigner
// uses for sessions/refresh tokens today; see that package's own doc
// comment for why it's untouched by this milestone) rather than folded
// into it, so the two signing systems' settings can never be confused
// with each other.
type AccessTokenConfig struct {
	// Issuer is this service's `iss` claim value on every access token it
	// issues.
	Issuer string `mapstructure:"issuer"`
	// TTL bounds every access token's lifetime — see Validate, which caps
	// it outright. There is deliberately no way to override this per
	// request anywhere in this codebase.
	TTL time.Duration `mapstructure:"ttl"`
	// KeyID is the current signing key's `kid` — what a verifier's key
	// lookup keys on, and what rotating to a new key pair means changing.
	// No default (see Validate): an operator must set this explicitly.
	KeyID string `mapstructure:"key_id"`
	// PrivateKeyPEM/PrivateKeyPath both hold PEM-encoded PKCS#8 Ed25519
	// private key material — the actual secret, never a literal in source
	// or in configs/config.yaml. PrivateKeyPath, if set, wins over
	// PrivateKeyPEM: a mounted secret file is the more realistic
	// production mechanism than raw key bytes sitting in process
	// environment — the same "two ways to supply one value, one wins"
	// precedent DatabaseConfig.URL already sets in this file. Neither has
	// a default, the same deliberate omission jwt.signing_key and
	// database.password already make.
	PrivateKeyPEM  string `mapstructure:"private_key_pem"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
	// DefaultAudience is the `aud` claim self-issued access tokens carry —
	// login and refresh both mint a token for this service's own API,
	// never a client-chosen value (see Milestone 5B's report: the refresh
	// request body is exactly {"refresh_token": "..."}, with no audience
	// field for a client to set).
	DefaultAudience string `mapstructure:"default_audience"`
}

// RefreshTokenConfig configures service.RefreshTokenService (Milestone
// 5B) — deliberately its own section rather than reusing
// JWTConfig.RefreshTokenTTL, which stays the old util.JWTSigner-based
// AuthService.RefreshToken flow's own knob (see that method's doc comment
// on why it's untouched). There is deliberately no per-request override
// anywhere in this codebase for this value.
type RefreshTokenConfig struct {
	TTL time.Duration `mapstructure:"ttl"`
}

// LeaseConfig configures service.LeaseService's TTL rules (Sprint 5 Task
// 2) — the same "requested TTL, clamped to [MinTTL, MaxTTL], defaulting
// to DefaultTTL when unset" shape the objective's own TTL section
// describes. There is deliberately no per-request override of MaxTTL
// anywhere in this codebase — a caller can only ever request a *shorter*
// effective TTL than the ceiling this config fixes, never a longer one
// (see LeaseService.effectiveTTL's own doc comment).
type LeaseConfig struct {
	MinTTL time.Duration `mapstructure:"min_ttl"`
	// DefaultTTL is used when a lease-creation request omits ttl
	// entirely — never left as "0 means unlimited," which the objective's
	// own "never allow a client to request an arbitrary unlimited TTL"
	// instruction rules out as a valid interpretation of an absent value
	// too.
	DefaultTTL time.Duration `mapstructure:"default_ttl"`
	MaxTTL     time.Duration `mapstructure:"max_ttl"`
	// MaxRenewableLifetime bounds a lease's total lifetime across every
	// renewal combined, measured from its original CreatedAt — not just
	// each individual renewal's own TTL ceiling (MaxTTL). Without this, a
	// renewable lease with a short MaxTTL could still be renewed
	// indefinitely, one MaxTTL-sized window at a time, forever — exactly
	// the "do not allow indefinite renewal unless explicitly configured"
	// case the objective calls out by name.
	MaxRenewableLifetime time.Duration `mapstructure:"max_renewable_lifetime"`
	// CleanupInterval controls how often the background worker in
	// cmd/server/main.go sweeps overdue leases via
	// LeaseService.ExpireOverdue. This is a best-effort, defense-in-depth
	// tidy-up only — authorization already checks entity.Lease.IsExpired
	// live on every request, so a slow or stalled cleanup worker never
	// lets an expired lease remain usable (see LeaseService.Get/Renew's
	// own doc comments). A non-positive value disables the worker
	// entirely.
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
}

// PostgresProvisionerConfig configures the dedicated database connection
// leasing.PostgresCredentialProvider (Sprint 5 Task 3) uses to create and
// revoke temporary PostgreSQL roles — deliberately never the same
// connection or credential as Config.Database, the application's own,
// otherwise-unprivileged connection. A real deployment points this at a
// separate `vault-provisioner` database identity holding exactly the
// privileges documented on PostgresCredentialProvider's own doc comment
// (CREATEROLE plus GRANT authority over the configured role templates'
// databases/schemas — never SUPERUSER). Enabled defaults to false: the
// "postgres" lease type is simply never registered with LeaseService
// until an operator explicitly configures this, the same
// AUTH_SECRETS_DEV_MASTER_KEY-gated pattern SecretsConfig already
// establishes for an entire optional subsystem.
type PostgresProvisionerConfig struct {
	Enabled bool `mapstructure:"enabled"`
	// URL/Host/Port/User/Password/Name/SSLMode mirror DatabaseConfig's own
	// shape exactly (see that type's own doc comment on the URL-wins
	// precedence) — a second, independently-configured connection, never
	// derived from Config.Database.
	URL             string        `mapstructure:"url"`
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	User            string        `mapstructure:"user"`
	Password        string        `mapstructure:"password"`
	Name            string        `mapstructure:"name"`
	SSLMode         string        `mapstructure:"sslmode"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
	// RoleTemplates is the entire operator-configured catalog of
	// selectable dynamic-credential roles — see PostgresRoleTemplate's
	// own doc comment. A lease-creation request's own "role" field must
	// name one of these by Name; there is no request field, anywhere,
	// that lets a caller supply a database, schema, or privilege list
	// directly. This is what makes "the caller must not be able to
	// select an arbitrary privileged database role" true by construction
	// rather than by a runtime check that could have a gap.
	RoleTemplates []PostgresRoleTemplate `mapstructure:"role_templates"`
}

// DSN mirrors DatabaseConfig.DSN exactly — see that method's own doc
// comment.
func (c PostgresProvisionerConfig) DSN() string {
	if c.URL != "" {
		return c.URL
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.User, c.Password, c.Host, c.Port, c.Name, c.SSLMode)
}

// postgresAllowedPrivileges is the entire universe of privilege strings a
// PostgresRoleTemplate may grant — deliberately an allowlist, not a
// denylist: SUPERUSER/CREATEDB/CREATEROLE/REPLICATION/BYPASSRLS (role
// *attributes*, not GRANT-able privileges at all) can never appear here
// regardless of what an operator writes in configs/config.yaml, because
// PostgresCredentialProvider's own CREATE ROLE statement never has a
// code path that could interpolate one in — see that type's own doc
// comment. This allowlist exists purely to reject an operator typo (a
// misspelled privilege Postgres itself would reject anyway, but with a
// worse error) before it ever reaches a real database.
var postgresAllowedPrivileges = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"TRUNCATE": true, "REFERENCES": true, "TRIGGER": true, "USAGE": true, "EXECUTE": true,
}

// PostgresRoleTemplate is one selectable entry in an operator's
// role-template catalog — e.g. "payment-readonly" -> database
// "payment_db", schema "public", privilege "SELECT" only. Name is what a
// lease-creation request's own "role" field names; Database/Schemas/
// Privileges are never visible to, or overridable by, the request that
// selects this template.
type PostgresRoleTemplate struct {
	Name       string   `mapstructure:"name"`
	Database   string   `mapstructure:"database"`
	Schemas    []string `mapstructure:"schemas"`
	Privileges []string `mapstructure:"privileges"`
}

// RateLimitConfig configures internal/ratelimit's Redis-backed
// authentication abuse protection (Milestone 6C). It replaces the
// Sprint-1 RateLimitConfig{LoginPerMinute}, which nothing in this codebase
// ever read — dead config, not a value with existing behavior to
// preserve.
type RateLimitConfig struct {
	// Enabled is a master switch — false skips construction of the Redis
	// client and abuse-protection component entirely (see
	// cmd/server/main.go), for a deployment that isn't ready to run Redis
	// yet. Defaults to true: for an authentication service, brute-force
	// protection is a security control, not an opt-in extra.
	Enabled bool `mapstructure:"enabled"`
	// FailClosed selects the posture when Redis is unreachable during the
	// pre-check: true rejects the authentication operation (a Redis
	// outage becomes a temporary authentication outage); false allows it
	// through unprotected (brute-force protection lapses, availability
	// doesn't). The Milestone 6C design review's explicit choice for an
	// enterprise secrets-management product is fail-closed. This applies
	// only to the pre-check — outcome recording (RecordFailure/
	// RecordSuccess) is always best-effort regardless of this setting; see
	// internal/ratelimit.AuthAbuseProtection's doc comment for why.
	FailClosed bool `mapstructure:"fail_closed"`
	// RetryAfter is the fixed value returned in every 429 response's
	// Retry-After header — deliberately not derived from any dimension's
	// actual remaining block time, so the header itself never reveals
	// which dimension triggered or how close to expiry a block is.
	RetryAfter time.Duration            `mapstructure:"retry_after"`
	Login      LoginRateLimitConfig     `mapstructure:"login"`
	Refresh    RefreshRateLimitConfig   `mapstructure:"refresh"`
	Bootstrap  BootstrapRateLimitConfig `mapstructure:"bootstrap"`
	// ServiceAccountAuth (Sprint 5 Task 1) guards
	// POST /service-accounts/{id}/token — the machine-credential
	// equivalent of Login above, same three-dimension shape (IP, the
	// service account ID in place of an email, and their pairing).
	ServiceAccountAuth ServiceAccountAuthRateLimitConfig `mapstructure:"service_account_auth"`
	// API (Sprint 4 Task 4) configures internal/ratelimit.RedisAPIRateLimiter
	// — general request throttling for everything Login/Refresh/Bootstrap
	// above don't cover (secrets, secret-policies, users/roles, audit
	// search, registration, logout). A distinct mechanism from the
	// brute-force lockout above by design — see
	// internal/ratelimit's own package doc comment for the split.
	API APIRateLimitConfig `mapstructure:"api"`
}

// APIRateLimitConfig holds one RequestCategoryConfig per rate-limit
// category — see router.go's categorySecretsRead/etc. constants, which
// these mapstructure keys must match (cmd/server/main.go is the one
// place that translates a field here into a
// ratelimit.APIRateLimiterConfig.Categories map entry keyed by that
// constant's string value).
type APIRateLimitConfig struct {
	SecretsRead  RequestCategoryConfig `mapstructure:"secrets_read"`
	SecretsWrite RequestCategoryConfig `mapstructure:"secrets_write"`
	PolicyAdmin  RequestCategoryConfig `mapstructure:"policy_admin"`
	UserAdmin    RequestCategoryConfig `mapstructure:"user_admin"`
	AuditRead    RequestCategoryConfig `mapstructure:"audit_read"`
	AuthRegister RequestCategoryConfig `mapstructure:"auth_register"`
	AuthLogout   RequestCategoryConfig `mapstructure:"auth_logout"`
	// ServiceAccountAdmin (Sprint 5 Task 1) covers every
	// /v1/service-accounts* and /v1/api-keys* admin route — see
	// router.go's categoryServiceAccountAdmin.
	ServiceAccountAdmin RequestCategoryConfig `mapstructure:"service_account_admin"`
	// LeaseCreate/LeaseRead/LeaseRenew/LeaseRevoke (Sprint 5 Task 2) are
	// deliberately separate categories, not one shared "leases" category
	// — the objective's own "consider separate limits for lease
	// creation / renewal / revocation" instruction: creation is the
	// expensive, abuse-prone operation (it mints a real credential),
	// renewal only extends bookkeeping, and revocation is a safety
	// action an operator may need to perform in bulk during an incident
	// without it competing against normal creation traffic's budget.
	// LeaseRead (GET list/detail) is the generous, read-only category
	// every other resource family's own *Read category already
	// establishes a pattern for (categorySecretsRead, categoryAuditRead).
	LeaseCreate RequestCategoryConfig `mapstructure:"lease_create"`
	LeaseRead   RequestCategoryConfig `mapstructure:"lease_read"`
	LeaseRenew  RequestCategoryConfig `mapstructure:"lease_renew"`
	LeaseRevoke RequestCategoryConfig `mapstructure:"lease_revoke"`
}

// RequestCategoryConfig configures one general API rate-limit category —
// translated into a ratelimit.CategoryConfig by cmd/server/main.go, one
// WindowPolicy per identity type that's actually meaningful for that
// category (a zero Window or Limit means "not configured," translated to
// a nil *ratelimit.WindowPolicy — the same "nil means this dimension
// doesn't apply" convention OperationPolicy's own fields already follow).
// Not every field matters for every category: auth_register has no
// authenticated identity yet, so only IPWindow/IPLimit apply to it in
// practice; every other category is reached only by an already-
// authenticated caller (it sits behind requireAuth), so only
// User*/ServiceAccount* apply to those.
//
// FailOpen is this category's own posture when Redis is unreachable —
// see ratelimit.CategoryConfig's own doc comment for the reasoning behind
// why this is per-category, never one blanket setting for every category.
type RequestCategoryConfig struct {
	UserWindow           time.Duration `mapstructure:"user_window"`
	UserLimit            int64         `mapstructure:"user_limit"`
	ServiceAccountWindow time.Duration `mapstructure:"service_account_window"`
	ServiceAccountLimit  int64         `mapstructure:"service_account_limit"`
	IPWindow             time.Duration `mapstructure:"ip_window"`
	IPLimit              int64         `mapstructure:"ip_limit"`
	FailOpen             bool          `mapstructure:"fail_open"`
}

// LoginRateLimitConfig holds POST /auth/login's three dimensions — IP,
// account, and their pairing — each with its own detection window,
// failure threshold, and this operation's shared block duration.
type LoginRateLimitConfig struct {
	IPWindow      time.Duration `mapstructure:"ip_window"`
	IPLimit       int64         `mapstructure:"ip_limit"`
	AccountWindow time.Duration `mapstructure:"account_window"`
	AccountLimit  int64         `mapstructure:"account_limit"`
	PairWindow    time.Duration `mapstructure:"pair_window"`
	PairLimit     int64         `mapstructure:"pair_limit"`
	BlockDuration time.Duration `mapstructure:"block_duration"`
}

// ServiceAccountAuthRateLimitConfig holds POST /service-accounts/{id}/token's
// three dimensions — IP, the service account ID in place of an email
// account identifier, and their pairing — mirroring LoginRateLimitConfig's
// own shape exactly (see ratelimit.OperationServiceAccountAuth's own doc
// comment for why the identical Dimensions{IP, Account} struct applies
// unchanged to this operation too).
type ServiceAccountAuthRateLimitConfig struct {
	IPWindow             time.Duration `mapstructure:"ip_window"`
	IPLimit              int64         `mapstructure:"ip_limit"`
	ServiceAccountWindow time.Duration `mapstructure:"service_account_window"`
	ServiceAccountLimit  int64         `mapstructure:"service_account_limit"`
	PairWindow           time.Duration `mapstructure:"pair_window"`
	PairLimit            int64         `mapstructure:"pair_limit"`
	BlockDuration        time.Duration `mapstructure:"block_duration"`
}

// RefreshRateLimitConfig holds POST /auth/refresh's one dimension — IP
// only, per the Milestone 6C design review: a refresh token is already a
// high-entropy secret, not a guessable credential, so there is no account
// dimension to rate-limit before the token has even resolved to a user.
type RefreshRateLimitConfig struct {
	IPWindow      time.Duration `mapstructure:"ip_window"`
	IPLimit       int64         `mapstructure:"ip_limit"`
	BlockDuration time.Duration `mapstructure:"block_duration"`
}

// BootstrapRateLimitConfig holds POST /platform/bootstrap's one
// dimension — IP only, the same reasoning RefreshRateLimitConfig's own
// doc comment gives: there is no account to rate-limit against yet, since
// this endpoint's entire job is creating the platform's first one. The
// defaults are deliberately far stricter than login's (see setDefaults) —
// this endpoint creates the most privileged account the platform will
// ever have, and legitimate traffic against it is, at most, a handful of
// requests during initial setup.
type BootstrapRateLimitConfig struct {
	IPWindow      time.Duration `mapstructure:"ip_window"`
	IPLimit       int64         `mapstructure:"ip_limit"`
	BlockDuration time.Duration `mapstructure:"block_duration"`
}

// SecretsConfig configures secrets.DevKeyProvider (Sprint 3 Phase 2) — the
// development-only local key provider backing the Secrets Engine's
// envelope encryption. DevMasterKey is a base64-encoded 256-bit AES key;
// like jwt.signing_key and access_token.private_key_pem, it has no
// default (see setDefaults) and is never a literal in source.
//
// Deliberately still not required by Validate below (see Phase 4's own
// note in cmd/server/main.go): this codebase still has no production-grade
// KeyProvider (AWS KMS, Azure Key Vault, GCP KMS, an HSM) — only
// DevKeyProvider, which is explicitly development-only (see its own doc
// comment). Requiring this field in every environment would force a
// production deployment to configure a key this codebase's own
// documentation says must never be used there. Instead, Phase 4's
// cmd/server/main.go wires the Secrets Engine (repository, encryption
// service, SecretService, and the /v1/secrets routes) only when
// DevMasterKey is actually set, and simply leaves /v1/secrets unregistered
// otherwise — an honest "not configured" state, not a forced,
// wrong-for-production requirement.
//
// DevMasterKeyID has a default (see setDefaults) — it is this phase's
// only key, given a stable, human-readable label the same way
// access_token.key_id labels its own key, but with nothing to rotate to
// yet, so an operator-chosen value isn't required the way
// access_token.key_id's is.
type SecretsConfig struct {
	DevMasterKey   string `mapstructure:"dev_master_key"`
	DevMasterKeyID string `mapstructure:"dev_master_key_id"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// Load builds a Viper instance, applies defaults, reads an optional
// config file, binds environment variables, unmarshals into Config, and
// validates the result. It returns an error rather than a partially-valid
// Config on any failure — see Validate for why that matters more here
// than in most packages.
func Load() (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath(".")
	if err := v.ReadInConfig(); err != nil {
		if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
			return nil, fmt.Errorf("config: reading config file: %w", err)
		}
		// No file is the expected, normal case in a container: production
		// configuration is 100% environment variables, deliberately, so
		// there is never a file an operator could forget to mount.
	}

	// AutomaticEnv + the replacer let AUTH_JWT_SIGNING_KEY satisfy the
	// nested key "jwt.signing_key". The gotcha this works around: Viper's
	// AutomaticEnv only checks the environment for a key it already
	// "knows about" — one that reached Viper via a default, a config
	// file, or an explicit bind. setDefaults covers every operational
	// key; the two secrets deliberately have no default (see that
	// function's comment), so they need the explicit BindEnv calls below
	// instead — omitting them silently breaks env-var loading for exactly
	// those two fields, which is the failure mode a passing test suite
	// would otherwise never catch.
	v.SetEnvPrefix("AUTH")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := v.BindEnv("jwt.signing_key"); err != nil {
		return nil, fmt.Errorf("config: bind jwt.signing_key: %w", err)
	}
	if err := v.BindEnv("database.password"); err != nil {
		return nil, fmt.Errorf("config: bind database.password: %w", err)
	}
	// database.url has no default either (DatabaseConfig.DSN prefers it
	// over the composed host/port/user/name fields when set — see that
	// method's own doc comment) — the same gotcha as every other
	// no-default field in this function: without this bind,
	// AUTH_DATABASE_URL is silently never read at all, and DSN() silently
	// falls back to the composed default (host=localhost, name=authdb),
	// which can be a real, existing database that just isn't the one the
	// caller meant to point at, rather than a loud connection failure.
	if err := v.BindEnv("database.url"); err != nil {
		return nil, fmt.Errorf("config: bind database.url: %w", err)
	}
	// access_token.key_id/private_key_pem/private_key_path have no
	// default either (see AccessTokenConfig's doc comment), so they need
	// the same explicit BindEnv treatment as the two secrets above —
	// exactly the gotcha this comment block already warns about.
	if err := v.BindEnv("access_token.key_id"); err != nil {
		return nil, fmt.Errorf("config: bind access_token.key_id: %w", err)
	}
	if err := v.BindEnv("access_token.private_key_pem"); err != nil {
		return nil, fmt.Errorf("config: bind access_token.private_key_pem: %w", err)
	}
	if err := v.BindEnv("access_token.private_key_path"); err != nil {
		return nil, fmt.Errorf("config: bind access_token.private_key_path: %w", err)
	}
	// redis.password has no default either — unlike database.password,
	// Validate doesn't require it to be set (see RedisConfig's doc
	// comment), but AutomaticEnv still needs the explicit bind to find
	// AUTH_REDIS_PASSWORD at all, the same gotcha as every other no-default
	// field above.
	if err := v.BindEnv("redis.password"); err != nil {
		return nil, fmt.Errorf("config: bind redis.password: %w", err)
	}
	// secrets.dev_master_key has no default either, the same no-default
	// rule every other secret in this function follows.
	if err := v.BindEnv("secrets.dev_master_key"); err != nil {
		return nil, fmt.Errorf("config: bind secrets.dev_master_key: %w", err)
	}
	// postgres_provisioner.{host,port,user,password,name,url} have no
	// default and (deliberately — see configs/config.yaml's own "never put
	// a secret here" rule) no config-file entry either: this whole
	// connection is a second, independently-privileged credential, most of
	// which (password certainly, but host/port/user/name too, since they
	// jointly name a specific, sensitive provisioning connection) has no
	// business sitting in a committed file next to database.host's own
	// harmless "localhost" default. Before this fix, that meant there was
	// no way to actually populate this connection via environment variable
	// at all — AutomaticEnv silently never sees AUTH_POSTGRES_PROVISIONER_*
	// for a key with no default, no file entry, and no explicit bind — an
	// operator could set postgres_provisioner.enabled=true and every one of
	// these env vars and Load would still see empty strings for all of
	// them, the exact silent-failure gotcha this function's own comment
	// block above already warns about for every other secret it lists.
	for _, key := range []string{
		"postgres_provisioner.host", "postgres_provisioner.port", "postgres_provisioner.user",
		"postgres_provisioner.password", "postgres_provisioner.name", "postgres_provisioner.url",
	} {
		if err := v.BindEnv(key); err != nil {
			return nil, fmt.Errorf("config: bind %s: %w", key, err)
		}
	}

	var cfg Config
	decodeHook := mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	)
	if err := v.Unmarshal(&cfg, viper.DecodeHook(decodeHook)); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &cfg, nil
}

// setDefaults covers every operational (non-secret) field. Two things are
// deliberately absent: jwt.signing_key and database.password. Giving them
// a real default would defeat Validate's whole point (a default a
// deployment forgot to override is indistinguishable from a real secret
// until it's exploited); giving them an empty-string default would read
// as "the default password is empty string," which is worse than no
// default at all. Load registers them with BindEnv instead, purely so
// AutomaticEnv can still find their environment variables.
func setDefaults(v *viper.Viper) {
	v.SetDefault("environment", "development")

	v.SetDefault("server.http_addr", ":8080")
	v.SetDefault("server.read_timeout", 10*time.Second)
	v.SetDefault("server.write_timeout", 15*time.Second)
	v.SetDefault("server.shutdown_timeout", 15*time.Second)
	v.SetDefault("server.allowed_origins", []string{})
	v.SetDefault("server.trusted_proxies", []string{})

	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "authsvc")
	v.SetDefault("database.name", "authdb")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 25)
	v.SetDefault("database.conn_max_lifetime", 5*time.Minute)
	v.SetDefault("database.conn_max_idle_time", 2*time.Minute)

	v.SetDefault("jwt.access_token_ttl", 15*time.Minute)
	v.SetDefault("jwt.refresh_token_ttl", 30*24*time.Hour)

	v.SetDefault("access_token.issuer", "auth-service")
	// Milestone 5A: "a secure default appropriate for our architecture,
	// initially around 10 minutes" — access tokens must be short-lived;
	// see Validate's hard cap for the enforcement half of that statement.
	v.SetDefault("access_token.ttl", 10*time.Minute)
	v.SetDefault("access_token.default_audience", "auth-service")

	// Milestone 5B: "a secure initial default around 7 days" — deliberately
	// its own setting rather than reusing jwt.refresh_token_ttl (above),
	// which stays the old util.JWTSigner-based flow's own knob; the same
	// separation AccessTokenConfig already keeps from JWTConfig.
	v.SetDefault("refresh_token.ttl", 7*24*time.Hour)

	v.SetDefault("redis.addr", "localhost:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.dial_timeout", 5*time.Second)
	v.SetDefault("redis.read_timeout", 3*time.Second)
	v.SetDefault("redis.write_timeout", 3*time.Second)
	v.SetDefault("redis.pool_size", 10)

	// Milestone 6C: an enterprise secrets-management product treats
	// authentication abuse protection as a security control, not an
	// optimization — enabled and fail-closed by default (see
	// RateLimitConfig's own doc comment for the fail-closed tradeoff).
	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.fail_closed", true)
	v.SetDefault("rate_limit.retry_after", 60*time.Second)

	v.SetDefault("rate_limit.login.ip_window", 15*time.Minute)
	v.SetDefault("rate_limit.login.ip_limit", 20)
	v.SetDefault("rate_limit.login.account_window", 15*time.Minute)
	v.SetDefault("rate_limit.login.account_limit", 5)
	v.SetDefault("rate_limit.login.pair_window", 15*time.Minute)
	v.SetDefault("rate_limit.login.pair_limit", 5)
	v.SetDefault("rate_limit.login.block_duration", 15*time.Minute)

	v.SetDefault("rate_limit.refresh.ip_window", 15*time.Minute)
	v.SetDefault("rate_limit.refresh.ip_limit", 30)
	v.SetDefault("rate_limit.refresh.block_duration", 15*time.Minute)

	v.SetDefault("rate_limit.bootstrap.ip_window", 1*time.Hour)
	v.SetDefault("rate_limit.bootstrap.ip_limit", 5)
	v.SetDefault("rate_limit.bootstrap.block_duration", 1*time.Hour)

	// Sprint 5 Task 1 — machine-credential brute-force protection,
	// mirroring rate_limit.login's own defaults: a service account's
	// credential is higher-entropy than a human password (see
	// util.NewAPIKey), so a somewhat higher account_limit than login's 5
	// is still conservative — enough headroom for a workload that
	// legitimately re-authenticates often without diluting the
	// protection a single leaked-but-wrong-service-account guess gets.
	v.SetDefault("rate_limit.service_account_auth.ip_window", 15*time.Minute)
	v.SetDefault("rate_limit.service_account_auth.ip_limit", 30)
	v.SetDefault("rate_limit.service_account_auth.service_account_window", 15*time.Minute)
	v.SetDefault("rate_limit.service_account_auth.service_account_limit", 10)
	v.SetDefault("rate_limit.service_account_auth.pair_window", 15*time.Minute)
	v.SetDefault("rate_limit.service_account_auth.pair_limit", 10)
	v.SetDefault("rate_limit.service_account_auth.block_duration", 15*time.Minute)

	// Sprint 4 Task 4 — general API request throttling. Read-heavy,
	// lower-risk categories (secrets_read, audit_read) default
	// fail_open: true, so a Redis outage doesn't make read traffic
	// unusable; write/admin categories default fail_open: false, since
	// uncontrolled write volume during an outage is a real risk worth
	// trading availability for. auth_register defaults fail_open: false
	// too — an unthrottled registration endpoint during a Redis outage is
	// exactly the mass-account-creation risk this category exists to
	// close. Service-account limits default higher than user limits
	// throughout, matching the objective's own "service accounts may
	// legitimately make many requests... do not simply remove limits"
	// instruction — still bounded, just a wider budget.
	v.SetDefault("rate_limit.api.secrets_read.user_window", time.Minute)
	v.SetDefault("rate_limit.api.secrets_read.user_limit", 100)
	v.SetDefault("rate_limit.api.secrets_read.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.secrets_read.service_account_limit", 1000)
	v.SetDefault("rate_limit.api.secrets_read.fail_open", true)

	v.SetDefault("rate_limit.api.secrets_write.user_window", time.Minute)
	v.SetDefault("rate_limit.api.secrets_write.user_limit", 20)
	v.SetDefault("rate_limit.api.secrets_write.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.secrets_write.service_account_limit", 100)
	v.SetDefault("rate_limit.api.secrets_write.fail_open", false)

	v.SetDefault("rate_limit.api.policy_admin.user_window", time.Minute)
	v.SetDefault("rate_limit.api.policy_admin.user_limit", 30)
	v.SetDefault("rate_limit.api.policy_admin.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.policy_admin.service_account_limit", 100)
	v.SetDefault("rate_limit.api.policy_admin.fail_open", false)

	v.SetDefault("rate_limit.api.user_admin.user_window", time.Minute)
	v.SetDefault("rate_limit.api.user_admin.user_limit", 60)
	v.SetDefault("rate_limit.api.user_admin.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.user_admin.service_account_limit", 200)
	v.SetDefault("rate_limit.api.user_admin.fail_open", false)

	v.SetDefault("rate_limit.api.audit_read.user_window", time.Minute)
	v.SetDefault("rate_limit.api.audit_read.user_limit", 30)
	v.SetDefault("rate_limit.api.audit_read.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.audit_read.service_account_limit", 100)
	v.SetDefault("rate_limit.api.audit_read.fail_open", true)

	v.SetDefault("rate_limit.api.auth_register.ip_window", 1*time.Hour)
	v.SetDefault("rate_limit.api.auth_register.ip_limit", 5)
	v.SetDefault("rate_limit.api.auth_register.fail_open", false)

	v.SetDefault("rate_limit.api.auth_logout.user_window", time.Minute)
	v.SetDefault("rate_limit.api.auth_logout.user_limit", 30)
	v.SetDefault("rate_limit.api.auth_logout.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.auth_logout.service_account_limit", 100)
	v.SetDefault("rate_limit.api.auth_logout.fail_open", true)

	// service_account_admin (Sprint 5 Task 1): human-administrator-only
	// traffic in practice (service accounts never call their own admin
	// API — they authenticate via the token endpoint instead), so this
	// mirrors user_admin's own limits and posture exactly.
	v.SetDefault("rate_limit.api.service_account_admin.user_window", time.Minute)
	v.SetDefault("rate_limit.api.service_account_admin.user_limit", 60)
	v.SetDefault("rate_limit.api.service_account_admin.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.service_account_admin.service_account_limit", 60)
	v.SetDefault("rate_limit.api.service_account_admin.fail_open", false)

	// Sprint 5 Task 2 — dynamic-secret lease TTL rules. Defaults chosen to
	// be short by default (30m) and bounded well below a full day at the
	// ceiling (1h max) — dynamic credentials are meant to be short-lived
	// by construction (the objective's own "temporary credentials"
	// framing), not a slower-to-rotate substitute for a static secret.
	// MaxRenewableLifetime (24h) bounds total lifetime across every
	// renewal combined, independent of how many individual MaxTTL-sized
	// renewals it would otherwise take to reach it.
	v.SetDefault("lease.min_ttl", 5*time.Minute)
	v.SetDefault("lease.default_ttl", 30*time.Minute)
	v.SetDefault("lease.max_ttl", 1*time.Hour)
	v.SetDefault("lease.max_renewable_lifetime", 24*time.Hour)
	v.SetDefault("lease.cleanup_interval", 1*time.Minute)

	v.SetDefault("rate_limit.api.lease_create.user_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_create.user_limit", 10)
	v.SetDefault("rate_limit.api.lease_create.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_create.service_account_limit", 30)
	v.SetDefault("rate_limit.api.lease_create.fail_open", false)

	v.SetDefault("rate_limit.api.lease_read.user_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_read.user_limit", 60)
	v.SetDefault("rate_limit.api.lease_read.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_read.service_account_limit", 200)
	v.SetDefault("rate_limit.api.lease_read.fail_open", true)

	v.SetDefault("rate_limit.api.lease_renew.user_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_renew.user_limit", 20)
	v.SetDefault("rate_limit.api.lease_renew.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_renew.service_account_limit", 60)
	v.SetDefault("rate_limit.api.lease_renew.fail_open", false)

	v.SetDefault("rate_limit.api.lease_revoke.user_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_revoke.user_limit", 30)
	v.SetDefault("rate_limit.api.lease_revoke.service_account_window", time.Minute)
	v.SetDefault("rate_limit.api.lease_revoke.service_account_limit", 60)
	// fail_open: true — a Redis outage must not prevent an operator from
	// revoking a lease during an incident (the exact scenario
	// categoryServiceAccountAdmin's own write categories deliberately
	// fail closed for is precisely the opposite risk here: revocation is
	// a safety action, throttling it away during an outage is the wrong
	// default).
	v.SetDefault("rate_limit.api.lease_revoke.fail_open", true)

	// postgres_provisioner (Sprint 5 Task 3): enabled defaults to false —
	// see PostgresProvisionerConfig's own doc comment. Pool defaults are
	// deliberately small: this connection only ever runs brief DDL
	// (CREATE/ALTER/DROP ROLE, a handful of GRANTs), never application
	// query traffic, so it needs nowhere near Config.Database's own pool
	// sizing.
	v.SetDefault("postgres_provisioner.enabled", false)
	v.SetDefault("postgres_provisioner.sslmode", "disable")
	v.SetDefault("postgres_provisioner.max_open_conns", 5)
	v.SetDefault("postgres_provisioner.max_idle_conns", 5)
	v.SetDefault("postgres_provisioner.conn_max_lifetime", 5*time.Minute)
	v.SetDefault("postgres_provisioner.conn_max_idle_time", 2*time.Minute)

	v.SetDefault("secrets.dev_master_key_id", "dev-key-1")

	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
}

var validEnvironments = map[string]bool{"development": true, "staging": true, "production": true}

// Validate fails closed: anything a missing/malformed setting could turn
// into (an open CORS policy, an unbounded connection pool, a forgeable
// JWT) is worse than refusing to start. See README.md's "why not
// hardcode" section — this method is the enforcement half of that
// argument; Load's defaults are the convenience half.
func (c Config) Validate() error {
	var errs []string

	if !validEnvironments[c.Environment] {
		errs = append(errs, fmt.Sprintf("environment %q must be one of development, staging, production", c.Environment))
	}

	if c.Database.URL == "" {
		if c.Database.Host == "" || c.Database.Name == "" {
			errs = append(errs, "database.host and database.name are required when database.url is not set")
		}
		if c.Database.Password == "" && c.Environment != "development" {
			errs = append(errs, "database.password is required outside development")
		}
	}

	if len(c.JWT.SigningKey) < 32 {
		errs = append(errs, "jwt.signing_key is required and must be at least 32 characters")
	}
	if c.JWT.AccessTokenTTL <= 0 {
		errs = append(errs, "jwt.access_token_ttl must be positive")
	}
	if c.JWT.RefreshTokenTTL <= c.JWT.AccessTokenTTL {
		errs = append(errs, "jwt.refresh_token_ttl must be longer than jwt.access_token_ttl")
	}

	if c.AccessToken.Issuer == "" {
		errs = append(errs, "access_token.issuer must not be empty")
	}
	if c.AccessToken.TTL <= 0 {
		errs = append(errs, "access_token.ttl must be positive")
	} else if c.AccessToken.TTL > time.Hour {
		// Not just floored, capped: Milestone 5A requires access tokens
		// to be short-lived, not merely "positive" — 1h is a generous
		// outer bound for what "short-lived" can mean here.
		errs = append(errs, "access_token.ttl must not exceed 1h — access tokens must be short-lived")
	}
	if c.AccessToken.KeyID == "" {
		errs = append(errs, "access_token.key_id is required")
	}
	if c.AccessToken.PrivateKeyPEM == "" && c.AccessToken.PrivateKeyPath == "" {
		errs = append(errs, "access_token.private_key_pem or access_token.private_key_path is required")
	}
	if c.AccessToken.DefaultAudience == "" {
		errs = append(errs, "access_token.default_audience must not be empty")
	}
	// Milestone 5A left the two checks above out: nothing constructed a
	// real security.TokenService yet, so requiring them only broke tests
	// for no live safety benefit. Milestone 5B's cmd/server/main.go now
	// does construct one — see RefreshTokenService's wiring — so the
	// fail-closed guarantee belongs here now, same as jwt.signing_key.

	if c.RefreshToken.TTL <= 0 {
		errs = append(errs, "refresh_token.ttl must be positive")
	}

	if c.RateLimit.Enabled {
		if c.RateLimit.RetryAfter <= 0 {
			errs = append(errs, "rate_limit.retry_after must be positive")
		}
		type namedLimit struct {
			field string
			d     time.Duration
			n     int64
		}
		for _, l := range []namedLimit{
			{"rate_limit.login.ip", c.RateLimit.Login.IPWindow, c.RateLimit.Login.IPLimit},
			{"rate_limit.login.account", c.RateLimit.Login.AccountWindow, c.RateLimit.Login.AccountLimit},
			{"rate_limit.login.pair", c.RateLimit.Login.PairWindow, c.RateLimit.Login.PairLimit},
			{"rate_limit.refresh.ip", c.RateLimit.Refresh.IPWindow, c.RateLimit.Refresh.IPLimit},
			{"rate_limit.bootstrap.ip", c.RateLimit.Bootstrap.IPWindow, c.RateLimit.Bootstrap.IPLimit},
		} {
			if l.d <= 0 {
				errs = append(errs, l.field+"_window must be positive")
			}
			if l.n <= 0 {
				errs = append(errs, l.field+"_limit must be positive")
			}
		}
		if c.RateLimit.Login.BlockDuration <= 0 {
			errs = append(errs, "rate_limit.login.block_duration must be positive")
		}
		if c.RateLimit.Refresh.BlockDuration <= 0 {
			errs = append(errs, "rate_limit.refresh.block_duration must be positive")
		}
		if c.RateLimit.Bootstrap.BlockDuration <= 0 {
			errs = append(errs, "rate_limit.bootstrap.block_duration must be positive")
		}
	}

	// PostgresProvisioner (Sprint 5 Task 3): validated only when enabled —
	// an operator who never sets postgres_provisioner.enabled never sees
	// the "postgres" lease type registered at all (cmd/server/main.go),
	// so there is nothing here to fail closed on. Every check below
	// exists to catch a misconfiguration before it ever reaches a real
	// database: an empty/duplicate template name, an unknown privilege
	// string, or a template naming no database at all.
	if c.PostgresProvisioner.Enabled {
		p := c.PostgresProvisioner
		if p.URL == "" && (p.Host == "" || p.Name == "") {
			errs = append(errs, "postgres_provisioner.host and postgres_provisioner.name are required when postgres_provisioner.url is not set")
		}
		if len(p.RoleTemplates) == 0 {
			errs = append(errs, "postgres_provisioner.role_templates must contain at least one entry when postgres_provisioner.enabled is true")
		}
		seenNames := map[string]bool{}
		for _, t := range p.RoleTemplates {
			if t.Name == "" {
				errs = append(errs, "postgres_provisioner.role_templates: every template must have a non-empty name")
				continue
			}
			if seenNames[t.Name] {
				errs = append(errs, fmt.Sprintf("postgres_provisioner.role_templates: duplicate template name %q", t.Name))
			}
			seenNames[t.Name] = true
			if t.Database == "" {
				errs = append(errs, fmt.Sprintf("postgres_provisioner.role_templates[%q]: database must not be empty", t.Name))
			}
			if len(t.Privileges) == 0 {
				errs = append(errs, fmt.Sprintf("postgres_provisioner.role_templates[%q]: privileges must contain at least one entry", t.Name))
			}
			for _, priv := range t.Privileges {
				if !postgresAllowedPrivileges[strings.ToUpper(priv)] {
					errs = append(errs, fmt.Sprintf("postgres_provisioner.role_templates[%q]: privilege %q is not allowed — must be one of SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, USAGE, EXECUTE", t.Name, priv))
				}
			}
			if len(t.Schemas) == 0 {
				errs = append(errs, fmt.Sprintf("postgres_provisioner.role_templates[%q]: schemas must contain at least one entry", t.Name))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
