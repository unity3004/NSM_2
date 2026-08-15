package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/logging"
)

// IdentityType distinguishes who a request is being counted against —
// see the objective's own "Design rate limits that distinguish: human
// users, service accounts, administrators" requirement. There is
// deliberately no separate "administrator" identity type: an
// administrator is still a user (IdentityUser), and the actual
// distinction the objective asks for is expressed instead through
// *category* — admin-only endpoint groups (policy-admin, user-admin,
// audit-read) already get their own, separately configured limits,
// distinct from a general user's secrets-read/write limits, without this
// package needing to know or trust anything about a caller's roles (a
// per-request permission check the rate-limit layer has no business
// duplicating — see internal/middleware.RequirePermission, which already
// owns that decision and runs independently of this one).
type IdentityType string

const (
	IdentityIP             IdentityType = "ip"
	IdentityUser           IdentityType = "user"
	IdentityServiceAccount IdentityType = "service_account"
)

// RequestIdentity is one API rate-limit check's subject. ID is always a
// stable, opaque identifier — an IP address, entity.User.ID, or
// entity.ServiceAccount.ID — never an email or username (see the
// objective's own "do not use email as the primary distributed
// rate-limit identity" requirement: identifiers that can change must
// never be what a distributed counter is keyed on, or a user who changes
// their email starts a fresh limit for free, and worse, a new user who
// reuses a since-freed email inherits a stranger's exhausted one).
type RequestIdentity struct {
	Type IdentityType
	ID   string
}

// APIDecision is Allow's result. RetryAfter is only meaningful when
// !Allowed, and — unlike AuthAbuseProtection.Decision, which deliberately
// carries no such detail (see that type's own doc comment on why a
// brute-force block must never reveal how close to expiry it is) —
// here it's the real, TTL-derived remaining window: general API
// throttling has no "don't tip off an attacker" concern to weigh against
// giving a legitimate, well-behaved API client an accurate backoff hint.
// Transitioned reports whether *this specific call* is the one that just
// pushed the counter from allowed to limited — the same "audit the
// transition, not every repeated hit" signal RecordFailure's own
// `blocked` return already establishes a precedent for, so a caller can
// record a bounded rate_limit.exceeded audit event instead of one per
// request against an already-throttled identity.
type APIDecision struct {
	Allowed      bool
	RetryAfter   time.Duration
	Transitioned bool
}

// APIRateLimiter throttles general (non-authentication) API traffic:
// "how many requests may this identity make in category X per window,"
// never "block this identity for having failed too many times" — that
// remains AuthAbuseProtection's distinct job (see this package's own doc
// comment), unchanged and un-replaced by this type. See
// RedisAPIRateLimiter's own doc comment for the algorithm and the
// concurrency/failure-mode reasoning.
type APIRateLimiter interface {
	Allow(ctx context.Context, category string, identity RequestIdentity) (APIDecision, error)
}

// WindowPolicy is one identity type's limit within one category: at most
// Limit requests per Window, counted by a fixed window (see
// RedisAPIRateLimiter's own doc comment on why fixed-window, not sliding
// or token-bucket, is the right choice here).
type WindowPolicy struct {
	Window time.Duration
	Limit  int64
}

// CategoryConfig configures one rate-limit category (e.g.
// "secrets-read", "policy-admin", "audit-read") — the limit applied per
// identity type within it, and the posture Allow falls back to when
// Redis itself is unreachable. A nil identity-type field means that
// identity type is not limited at all in this category (mirroring
// OperationPolicy's identical "nil field means this dimension doesn't
// apply" convention for AuthAbuseProtection).
//
// FailOpen is deliberately per-category, not a single blanket setting for
// every category the way it might first seem simplest to make it: the
// objective is explicit that authentication abuse protection should
// prefer fail-closed while lower-risk endpoints may reasonably choose
// fail-open, and a single global switch cannot express both at once. The
// intended operational shape (see cmd/server/main.go's own construction)
// is FailOpen: true for read-heavy, lower-risk categories (secrets-read,
// audit-read — a Redis outage should not make the product unusable for
// read traffic) and FailOpen: false for write/admin categories
// (secrets-write, policy-admin, user-admin — where uncontrolled write
// volume during a Redis outage is a real risk worth accepting reduced
// availability to avoid).
type CategoryConfig struct {
	User           *WindowPolicy
	ServiceAccount *WindowPolicy
	IP             *WindowPolicy
	FailOpen       bool
}

func (c CategoryConfig) policyFor(t IdentityType) *WindowPolicy {
	switch t {
	case IdentityUser:
		return c.User
	case IdentityServiceAccount:
		return c.ServiceAccount
	case IdentityIP:
		return c.IP
	default:
		return nil
	}
}

// APIRateLimiterConfig is RedisAPIRateLimiter's construction-time
// configuration. A category with no entry is never rate-limited — Allow
// treats that as "allowed, no-op," the same convention
// AuthAbuseProtection.Check already establishes for an unrecognized
// operation — so a caller can pass a category this component doesn't yet
// know about without special-casing it.
type APIRateLimiterConfig struct {
	Categories map[string]CategoryConfig
}

// NoopAPIRateLimiter allows every request unconditionally — wired in
// when rate_limit.enabled is false, the same role NoopAuthAbuseProtection
// already plays, so callers can hold an APIRateLimiter dependency
// unconditionally regardless of whether Redis is configured.
type NoopAPIRateLimiter struct{}

func (NoopAPIRateLimiter) Allow(context.Context, string, RequestIdentity) (APIDecision, error) {
	return APIDecision{Allowed: true}, nil
}

// RedisAPIRateLimiter is the real, Redis-backed APIRateLimiter.
//
// Algorithm: a fixed window, exactly like RedisAuthAbuseProtection's own
// failure counters (see that type's own doc comment) — chosen for the
// same reason: it is the simplest algorithm that satisfies this task's
// actual requirements, it is already proven and tested elsewhere in this
// codebase, and reusing it here is "extend the existing architecture
// consistently" rather than introducing a second, different algorithm
// (sliding window, token bucket) this codebase would then need to
// maintain two mental models for. One Redis key per (category, identity
// type, identity) accumulates a request count via INCR, with EXPIRE set
// only on the key's first increment in a fresh window (so the TTL is
// never pushed back out by later requests — a genuine, bounded window,
// not an indefinitely-renewed one). All of this — the increment, the
// conditional EXPIRE, and reading back the remaining TTL for an accurate
// Retry-After — happens inside one Lua script, executed by Redis as a
// single atomic unit against any concurrent script or command touching
// the same key. That atomicity is what makes concurrent requests unable
// to race past the limit: two callers hitting INCR "at the same instant"
// are still serialized by Redis itself, so the Nth and (N+1)th requests
// are never both told they're within a limit of N.
//
// Known, accepted limitation (the "safeguard" a fixed window still
// needs): a burst straddling a window boundary can allow up to
// approximately 2x Limit requests within a short span (Limit at the very
// end of one window, Limit again at the very start of the next). This is
// the well-known fixed-window edge case, deliberately accepted here as
// the tradeoff for this algorithm's simplicity — see this task's own
// final report for why a sliding-window-log or token-bucket
// implementation (which would close this gap) is documented as future
// work rather than built now, per this task's own "choose the simplest
// algorithm that satisfies the current requirements" instruction.
//
// Redis operations per Allow call: exactly one round trip (the Lua
// script itself, which internally issues INCR, a conditional EXPIRE, and
// a TTL read against Redis's own local state — no additional network
// round trips). This matches RedisAuthAbuseProtection.RecordFailure's
// own "one script, one round trip" shape and keeps this middleware's
// per-request overhead to a single, small Redis call.
type RedisAPIRateLimiter struct {
	client *redis.Client
	cfg    APIRateLimiterConfig
}

func NewRedisAPIRateLimiter(client *redis.Client, cfg APIRateLimiterConfig) *RedisAPIRateLimiter {
	return &RedisAPIRateLimiter{client: client, cfg: cfg}
}

// apiRateLimitScript is RedisAPIRateLimiter.Allow's entire Redis
// footprint. KEYS[1] is the one counter key; ARGV[1]/ARGV[2] are the
// window (seconds) and limit. Returns {limited, ttl_seconds,
// transitioned} — see APIDecision's own doc comment for what each means.
var apiRateLimitScript = redis.NewScript(`
local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])

local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, window)
end

local ttl = redis.call('TTL', key)
if ttl < 0 then
    ttl = window
end

local limited = 0
local transitioned = 0
if count > limit then
    limited = 1
    if count == limit + 1 then
        transitioned = 1
    end
end

return {limited, ttl, transitioned}
`)

// Allow reports whether one request in category by identity may proceed.
// A Redis connectivity problem is resolved entirely here, per the
// category's configured FailOpen posture, and never returned to the
// caller as an error to interpret — the identical "decide, don't hand
// back a raw failure" contract AuthAbuseProtection.Check already
// establishes, applied to a different (and per-category configurable)
// failure posture.
func (r *RedisAPIRateLimiter) Allow(ctx context.Context, category string, identity RequestIdentity) (APIDecision, error) {
	cat, ok := r.cfg.Categories[category]
	if !ok {
		return APIDecision{Allowed: true}, nil
	}
	policy := cat.policyFor(identity.Type)
	if policy == nil || identity.ID == "" {
		return APIDecision{Allowed: true}, nil
	}

	key := r.key(category, identity.Type, identity.ID)
	res, err := apiRateLimitScript.Run(ctx, r.client, []string{key}, int64(policy.Window.Seconds()), policy.Limit).Slice()
	if err != nil {
		logging.FromContext(ctx).Error("redis API rate limiter unavailable; applying configured failure posture",
			zap.String("category", category), zap.String("identity_type", string(identity.Type)),
			zap.Bool("fail_open", cat.FailOpen), zap.Error(err))
		return APIDecision{Allowed: cat.FailOpen}, nil
	}

	limited, _ := res[0].(int64)
	ttl, _ := res[1].(int64)
	transitioned, _ := res[2].(int64)
	if limited == 1 {
		return APIDecision{Allowed: false, RetryAfter: time.Duration(ttl) * time.Second, Transitioned: transitioned == 1}, nil
	}
	return APIDecision{Allowed: true}, nil
}

// key never places a raw IP, user ID, or service-account ID into Redis —
// hashIdentifier (shared with RedisAuthAbuseProtection, defined in
// redis_limiter.go) is the one place either is turned into key material,
// the same SHA-256 scheme and the same reasoning: a Redis keyspace dump
// must not hand out a list of real identifiers in the clear.
func (r *RedisAPIRateLimiter) key(category string, identityType IdentityType, id string) string {
	return "ratelimit:api:" + category + ":" + string(identityType) + ":" + hashIdentifier(id)
}
