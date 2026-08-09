// Package logging builds and propagates the service's structured logger.
// It exists as its own package — not "just call zap.NewProduction() where
// needed" — for two reasons: (1) every process in this service (the HTTP
// server, a future migration-runner cmd/, a background job) should emit
// logs shaped the same way, so the *construction* of a logger belongs in
// one place; and (2) correlation — attaching a request's ID to every log
// line it produces, without every function down the call stack accepting
// a "requestID string" parameter — needs a context-propagation convention,
// which is what context.go provides.
package logging

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New builds the base *zap.Logger for the process, before any request
// exists — cmd/server/main.go calls this once at startup and derives every
// per-request logger from it via WithContext/FromContext.
//
// level: "debug" | "info" | "warn" | "error" (see the package doc on log
// levels in README.md for what belongs at each one).
// format: "json" (every real deployment) or "console" (readable, colorized,
// for a developer's terminal — never used in production because it isn't
// machine-parseable).
func New(level, format, environment, serviceName string) (*zap.Logger, error) {
	zapLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		return nil, fmt.Errorf("logging: invalid level %q: %w", level, err)
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "timestamp"
	encoderCfg.MessageKey = "message"
	encoderCfg.LevelKey = "level"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderCfg.EncodeLevel = zapcore.LowercaseLevelEncoder
	encoderCfg.EncodeDuration = zapcore.StringDurationEncoder

	var encoder zapcore.Encoder
	switch format {
	case "console":
		consoleCfg := encoderCfg
		consoleCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(consoleCfg)
	default:
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	}

	core := zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), zapLevel)

	opts := []zap.Option{
		zap.AddCaller(),
		// A stack trace on every Warn would bury the log stream in noise
		// nobody reads; a stack trace missing on every Error is the one
		// piece of context that would have made the incident five minutes
		// shorter. ErrorLevel is where that trade tips.
		zap.AddStacktrace(zapcore.ErrorLevel),
		// Attached to every line this logger (or anything derived from
		// it) ever emits — the fields a log aggregator filters *fleets*
		// by, as opposed to request-scoped fields like request_id, which
		// filter one request's lines out of everyone else's.
		zap.Fields(
			zap.String("service", serviceName),
			zap.String("environment", environment),
		),
	}
	if environment == "development" {
		opts = append(opts, zap.Development())
	}

	return zap.New(core, opts...), nil
}
