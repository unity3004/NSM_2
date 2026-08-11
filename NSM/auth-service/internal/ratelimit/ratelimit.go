// Package ratelimit implements Redis-backed authentication abuse
// protection (Milestone 6C) — brute-force, credential-stuffing, and
// refresh-token abuse defense, layered in front of the existing
// PostgreSQL-backed authentication logic, never replacing it. See
// AuthAbuseProtection's own doc comment for the exact division of
// responsibility between this package and the callers that use it.
package ratelimit

import "context"

// Operation names — typed as constants so a caller and a Config map key
// can never disagree by typo. Both are already in use: OperationLogin by
// AuthService.Login, OperationRefresh by RefreshTokenService.Refresh. New
// authentication endpoints add a new constant here and a matching Config
// entry, never a new method on AuthAbuseProtection.
const (
	OperationLogin     = "login"
	OperationRefresh   = "refresh"
	OperationBootstrap = "bootstrap"
)

// Dimensions identifies the independent axes an authentication attempt is
// evaluated against. IP is always a plain, normalized client address;
// Account is a plain, normalized account identifier (e.g. a normalized
// email) or empty when not yet known (the refresh pre-check, before a
// token resolves to a user). Callers never hash either value themselves —
// see AuthAbuseProtection's doc comment for why that's this package's job,
// not theirs.
type Dimensions struct {
	IP      string
	Account string
}

// Decision is Check's result. Allowed is the only field a caller acts on;
// there is deliberately no field describing *which* dimension or *how
// close* to a threshold an attempt was — that information exists only
// inside this package, never surfacing to a caller that might (even
// accidentally) let it reach an HTTP response.
type Decision struct {
	Allowed bool
}

// AuthAbuseProtection decides whether an authentication operation may
// proceed, and separately records what happened afterward, across
// multiple independent dimensions (IP, account identifier, and their
// pairing — see Dimensions). It knows nothing about passwords, JWTs, or
// refresh tokens — only opaque, pre-normalized identifiers a caller
// supplies — and it never duplicates the actual authentication decision
// itself: Check only ever answers "is this operation currently allowed,"
// never "is this password/token valid."
//
// operation is a plain string ("login", "refresh") so one implementation
// serves every authentication endpoint that adopts it, including future
// ones, without an interface change.
//
// Redis-failure handling — the security/availability tradeoff Milestone
// 6C's design review settled — is entirely internal to Check: a
// connectivity problem is never returned to the caller as an error to
// interpret. Check resolves it according to the configured fail-open/
// fail-closed posture and returns a plain Decision either way (see
// RedisAuthAbuseProtection's doc comment for exactly how). RecordFailure
// and RecordSuccess are the opposite case — by the time either is called,
// the real authentication decision (a password check, a token lookup) has
// already been made; a Redis problem at that point is telemetry/security-
// state bookkeeping that failed, not a reason to change a result already
// computed. Both are best-effort unconditionally, regardless of the
// configured posture.
type AuthAbuseProtection interface {
	Check(ctx context.Context, operation string, dims Dimensions) (Decision, error)
	// RecordFailure increments the failure counters for every non-empty
	// dimension in dims and applies temporary blocking if a threshold is
	// exceeded. blocked reports whether *this specific call* is what
	// caused a dimension to newly cross its threshold — callers use this
	// to write a bounded, transition-only audit event rather than one per
	// repeated attempt against an already-blocked dimension.
	RecordFailure(ctx context.Context, operation string, dims Dimensions) (blocked bool, err error)
	// RecordSuccess resets the counters a successful operation should
	// clear. It never resets an IP-only dimension — see
	// RedisAuthAbuseProtection's doc comment on why an IP's abuse state
	// must survive one successful attempt among many failures.
	RecordSuccess(ctx context.Context, operation string, dims Dimensions) error
}

// NoopAuthAbuseProtection allows every operation unconditionally.
// cmd/server/main.go wires this in when rate_limit.enabled is false, so
// AuthService/RefreshTokenService can hold an AuthAbuseProtection
// dependency unconditionally — never nil — regardless of whether an
// operator has Redis available yet.
type NoopAuthAbuseProtection struct{}

func (NoopAuthAbuseProtection) Check(context.Context, string, Dimensions) (Decision, error) {
	return Decision{Allowed: true}, nil
}

func (NoopAuthAbuseProtection) RecordFailure(context.Context, string, Dimensions) (bool, error) {
	return false, nil
}

func (NoopAuthAbuseProtection) RecordSuccess(context.Context, string, Dimensions) error {
	return nil
}
