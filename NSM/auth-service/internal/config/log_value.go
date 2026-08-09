package config

import (
	"strconv"

	"go.uber.org/zap/zapcore"
)

// MarshalLogObject implements zapcore.ObjectMarshaler, so
// `logger.Info("configuration loaded", zap.Object("config", cfg))` in
// cmd/server/main.go is always safe to call — the secrets a Config
// carries (database.password, jwt.signing_key) are exactly the fields a
// naive %+v, a zap.Any, or a default struct log would print in full.
// Logging the *resolved* config at startup is genuinely valuable for
// debugging ("why is this instance pointed at the wrong database") — this
// method is what makes doing that safe, by keeping redaction attached to
// the type instead of repeated (or forgotten) at every call site that
// wants to log a Config.
//
// This is the one place internal/config accepts a dependency on a logging
// library (zapcore, not the whole zap package) — a narrow, deliberate
// exception: implementing a small, well-known marshaling interface is not
// the kind of coupling Clean Architecture's dependency rule is protecting
// against (compare json.Marshaler or sql.Scanner), and the alternative —
// redacting these two fields by hand at every future call site that logs
// a Config — is exactly the kind of repetition that eventually gets
// forgotten once.
func (c Config) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("environment", c.Environment)
	enc.AddString("server.http_addr", c.Server.HTTPAddr)
	enc.AddString("database.host", c.Database.Host)
	enc.AddInt("database.port", c.Database.Port)
	enc.AddString("database.name", c.Database.Name)
	enc.AddString("database.password", redact(c.Database.Password))
	enc.AddString("jwt.signing_key", redact(c.JWT.SigningKey))
	enc.AddDuration("jwt.access_token_ttl", c.JWT.AccessTokenTTL)
	enc.AddDuration("jwt.refresh_token_ttl", c.JWT.RefreshTokenTTL)
	enc.AddInt("rate_limit.login_per_minute", c.RateLimit.LoginPerMinute)
	enc.AddString("log.level", c.Log.Level)
	return nil
}

func redact(secret string) string {
	if secret == "" {
		return "(unset)"
	}
	return "(redacted, len=" + strconv.Itoa(len(secret)) + ")"
}
