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
	Environment  string             `mapstructure:"environment"`
	Server       ServerConfig       `mapstructure:"server"`
	Database     DatabaseConfig     `mapstructure:"database"`
	Redis        RedisConfig        `mapstructure:"redis"`
	JWT          JWTConfig          `mapstructure:"jwt"`
	AccessToken  AccessTokenConfig  `mapstructure:"access_token"`
	RefreshToken RefreshTokenConfig `mapstructure:"refresh_token"`
	RateLimit    RateLimitConfig    `mapstructure:"rate_limit"`
	Log          LogConfig          `mapstructure:"log"`
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
	// TrustedProxies lists the CIDR ranges of reverse proxies/load
	// balancers this deployment sits behind — see util.ResolveClientIP's
	// own doc comment for exactly how this is used. Empty (the default)
	// means "no trusted proxy": every client-IP resolution ignores
	// X-Forwarded-For/X-Real-IP entirely and uses the TCP peer address
	// only, which is the only safe default for a deployment that hasn't
	// explicitly declared what sits in front of it — trusting either
	// header by default would let any direct client spoof its own
	// rate-limit/audit identity for free.
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
	RetryAfter time.Duration          `mapstructure:"retry_after"`
	Login      LoginRateLimitConfig   `mapstructure:"login"`
	Refresh    RefreshRateLimitConfig `mapstructure:"refresh"`
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

// RefreshRateLimitConfig holds POST /auth/refresh's one dimension — IP
// only, per the Milestone 6C design review: a refresh token is already a
// high-entropy secret, not a guessable credential, so there is no account
// dimension to rate-limit before the token has even resolved to a user.
type RefreshRateLimitConfig struct {
	IPWindow      time.Duration `mapstructure:"ip_window"`
	IPLimit       int64         `mapstructure:"ip_limit"`
	BlockDuration time.Duration `mapstructure:"block_duration"`
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
	// redis.password has no default either — unlike database.password,
	// Validate doesn't require it to be set (see RedisConfig's doc
	// comment), but AutomaticEnv still needs the explicit bind to find
	// AUTH_REDIS_PASSWORD at all, the same gotcha as every other no-default
	// field above.
	if err := v.BindEnv("redis.password"); err != nil {
		return nil, fmt.Errorf("config: bind redis.password: %w", err)
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
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}
