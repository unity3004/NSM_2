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
	Environment string            `mapstructure:"environment"`
	Server      ServerConfig      `mapstructure:"server"`
	Database    DatabaseConfig    `mapstructure:"database"`
	JWT         JWTConfig         `mapstructure:"jwt"`
	AccessToken AccessTokenConfig `mapstructure:"access_token"`
	RateLimit   RateLimitConfig   `mapstructure:"rate_limit"`
	Log         LogConfig         `mapstructure:"log"`
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
}

type RateLimitConfig struct {
	LoginPerMinute int `mapstructure:"login_per_minute"`
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

	v.SetDefault("rate_limit.login_per_minute", 5)

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
	// access_token.key_id/private_key_pem/private_key_path are
	// deliberately not checked here — see AccessTokenConfig's doc
	// comment: nothing in this milestone's cmd/server/main.go constructs
	// a security.TokenService from them yet, and
	// security.LoadSigningKeySet already fails closed on missing or
	// malformed key material at the point a future caller actually does.

	if c.RateLimit.LoginPerMinute <= 0 {
		errs = append(errs, "rate_limit.login_per_minute must be positive")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
