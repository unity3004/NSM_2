package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/logging"
)

// DimensionPolicy configures one dimension's window, failure threshold,
// and temporary block duration. Window and BlockDuration are separate
// values, deliberately: a wide detection window (how long failures
// accumulate) and a block duration (how long a tripped dimension stays
// blocked once it has) answer different questions, and conflating them
// would make either one impossible to tune independently.
type DimensionPolicy struct {
	Window        time.Duration
	Limit         int64
	BlockDuration time.Duration
}

// OperationPolicy names which dimensions apply to one operation and their
// individual policies. A nil field means that dimension isn't rate-limited
// for this operation at all — Refresh's approved policy has no Account or
// Pair field set, matching Milestone 6C's design review exactly (refresh
// abuse is tracked by IP only).
type OperationPolicy struct {
	IP      *DimensionPolicy
	Account *DimensionPolicy
	Pair    *DimensionPolicy
}

// Config is RedisAuthAbuseProtection's construction-time configuration —
// the resolved, already-validated form of config.RateLimitConfig; see
// cmd/server/main.go for the translation.
type Config struct {
	// FailClosed selects the posture Check applies when Redis itself is
	// unreachable — see AuthAbuseProtection's doc comment and
	// RedisAuthAbuseProtection.Check's for exactly how. The Milestone 6C
	// design review's approved default is true.
	FailClosed bool
	// Operations maps an operation name (OperationLogin, OperationRefresh)
	// to its policy. An operation with no entry is never rate-limited —
	// Check/RecordFailure/RecordSuccess all treat that as "allowed, no-op"
	// rather than an error, so a caller can pass an operation this
	// component doesn't yet know about without special-casing it.
	Operations map[string]OperationPolicy
}

// RedisAuthAbuseProtection is the real, Redis-backed AuthAbuseProtection.
// It never stores a raw IP or account identifier in a Redis key — every
// key is built from a SHA-256 hash of the (already-normalized) value a
// caller supplies (see hashIdentifier) — and it never resets an
// IP-dimension counter from RecordSuccess, so one successful login from an
// otherwise-abusive IP doesn't erase that IP's accumulated signal.
type RedisAuthAbuseProtection struct {
	client *redis.Client
	cfg    Config
}

func NewRedisAuthAbuseProtection(client *redis.Client, cfg Config) *RedisAuthAbuseProtection {
	return &RedisAuthAbuseProtection{client: client, cfg: cfg}
}

// activeDimension is one dimension actually in play for a given call —
// present in the operation's policy *and* non-empty in the caller's
// Dimensions.
type activeDimension struct {
	name   string // "ip", "account", "pair" — also the Redis key segment
	policy DimensionPolicy
	// material is the raw (pre-hash), normalized identifier this
	// dimension's key is built from — never logged, never written to
	// Redis directly; see hashIdentifier.
	material string
}

func (op OperationPolicy) active(dims Dimensions) []activeDimension {
	var out []activeDimension
	if op.IP != nil && dims.IP != "" {
		out = append(out, activeDimension{name: "ip", policy: *op.IP, material: dims.IP})
	}
	if op.Account != nil && dims.Account != "" {
		out = append(out, activeDimension{name: "account", policy: *op.Account, material: dims.Account})
	}
	if op.Pair != nil && dims.IP != "" && dims.Account != "" {
		out = append(out, activeDimension{name: "pair", policy: *op.Pair, material: dims.IP + "|" + dims.Account})
	}
	return out
}

// Check reports whether operation is currently allowed for dims. A Redis
// connectivity problem is resolved entirely here, per Config.FailClosed,
// and never returned to the caller as an error: this method's contract is
// "decide," not "attempt and let the caller figure out what a failure
// means." The security/availability tradeoff this represents — a Redis
// outage with FailClosed=true rejects authentication operations entirely,
// rather than silently letting brute-force protection lapse — is the
// Milestone 6C design review's explicit, approved choice.
func (r *RedisAuthAbuseProtection) Check(ctx context.Context, operation string, dims Dimensions) (Decision, error) {
	op, ok := r.cfg.Operations[operation]
	if !ok {
		return Decision{Allowed: true}, nil
	}
	active := op.active(dims)
	if len(active) == 0 {
		return Decision{Allowed: true}, nil
	}

	keys := make([]string, len(active))
	for i, d := range active {
		keys[i] = r.blockKey(operation, d.name, d.material)
	}

	vals, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		logging.FromContext(ctx).Error("redis abuse-protection pre-check unavailable; applying configured failure posture",
			zap.String("operation", operation), zap.Bool("fail_closed", r.cfg.FailClosed), zap.Error(err))
		return Decision{Allowed: !r.cfg.FailClosed}, nil
	}
	for _, v := range vals {
		if v != nil {
			return Decision{Allowed: false}, nil
		}
	}
	return Decision{Allowed: true}, nil
}

// recordFailureScript atomically increments every active dimension's
// counter (creating it with the dimension's window as its TTL on the
// first increment, never resetting that TTL on subsequent ones — a fixed,
// not sliding, window), and sets a block key with the dimension's own
// BlockDuration the moment a counter reaches its Limit. Running this as
// one Lua script, rather than a GET-then-INCR-then-SET sequence in Go, is
// what makes two concurrent RecordFailure calls for the same identifier
// unable to both slip past the threshold: Redis executes the whole script
// as a single atomic unit against any other command or script.
//
// KEYS: pairs of (counterKey, blockKey) per active dimension, in order.
// ARGV: triples of (windowSeconds, limit, blockDurationSeconds) per
// dimension, in the same order.
// Returns: an array, one entry per dimension, 1 if that call is what just
// transitioned the dimension from not-blocked to blocked, 0 otherwise.
var recordFailureScript = redis.NewScript(`
local n = #KEYS / 2
local transitioned = {}
for i = 1, n do
    local counterKey = KEYS[2 * i - 1]
    local blockKey = KEYS[2 * i]
    local window = tonumber(ARGV[3 * i - 2])
    local limit = tonumber(ARGV[3 * i - 1])
    local blockDuration = tonumber(ARGV[3 * i])

    local count = redis.call('INCR', counterKey)
    if count == 1 then
        redis.call('EXPIRE', counterKey, window)
    end

    if count >= limit then
        local alreadyBlocked = redis.call('EXISTS', blockKey)
        redis.call('SET', blockKey, '1', 'EX', blockDuration)
        if alreadyBlocked == 1 then
            transitioned[i] = 0
        else
            transitioned[i] = 1
        end
    else
        transitioned[i] = 0
    end
end
return transitioned
`)

// RecordFailure is always best-effort: by the time it's called, the real
// authentication decision (a password check, a token lookup) has already
// been made. A Redis problem here is logged and returned to the caller as
// an informational error — see AuthService.Login/RefreshTokenService.Refresh,
// which log it and never let it change the response already computed.
func (r *RedisAuthAbuseProtection) RecordFailure(ctx context.Context, operation string, dims Dimensions) (bool, error) {
	op, ok := r.cfg.Operations[operation]
	if !ok {
		return false, nil
	}
	active := op.active(dims)
	if len(active) == 0 {
		return false, nil
	}

	keys := make([]string, 0, len(active)*2)
	argv := make([]any, 0, len(active)*3)
	for _, d := range active {
		keys = append(keys, r.counterKey(operation, d.name, d.material), r.blockKey(operation, d.name, d.material))
		argv = append(argv, int64(d.policy.Window.Seconds()), d.policy.Limit, int64(d.policy.BlockDuration.Seconds()))
	}

	res, err := recordFailureScript.Run(ctx, r.client, keys, argv...).Slice()
	if err != nil {
		logging.FromContext(ctx).Error("failed to record authentication failure in redis",
			zap.String("operation", operation), zap.Error(err))
		return false, err
	}

	blocked := false
	for _, v := range res {
		if n, ok := v.(int64); ok && n == 1 {
			blocked = true
		}
	}
	return blocked, nil
}

// RecordSuccess resets the account and pair dimensions' state — never the
// IP dimension, per Milestone 6C's approved reset policy: an IP that has
// been failing against many other identifiers must not have its abuse
// signal erased just because one of its attempts happened to succeed.
// Plain DELs, not a script: there is no threshold decision to make
// atomically here, and a delete racing a concurrent increment costs at
// most one extra allowed attempt, never a security hole.
func (r *RedisAuthAbuseProtection) RecordSuccess(ctx context.Context, operation string, dims Dimensions) error {
	op, ok := r.cfg.Operations[operation]
	if !ok {
		return nil
	}

	var keys []string
	for _, d := range op.active(dims) {
		if d.name == "ip" {
			continue
		}
		keys = append(keys, r.counterKey(operation, d.name, d.material), r.blockKey(operation, d.name, d.material))
	}
	if len(keys) == 0 {
		return nil
	}

	if err := r.client.Del(ctx, keys...).Err(); err != nil {
		logging.FromContext(ctx).Error("failed to reset abuse-protection counters in redis",
			zap.String("operation", operation), zap.Error(err))
		return err
	}
	return nil
}

func (r *RedisAuthAbuseProtection) counterKey(operation, dimension, material string) string {
	return "ratelimit:" + operation + ":" + dimension + ":counter:" + hashIdentifier(material)
}

func (r *RedisAuthAbuseProtection) blockKey(operation, dimension, material string) string {
	return "ratelimit:" + operation + ":" + dimension + ":block:" + hashIdentifier(material)
}

// hashIdentifier is the one place a raw IP or account identifier is
// turned into Redis key material — SHA-256 hex, matching the same
// approach util.HashToken already uses for session/refresh tokens (a
// different purpose — those hash secrets so a stolen database dump can't
// be replayed; this hashes identifiers so a database/keyspace dump
// doesn't hand out a list of real emails or IPs in the clear). Never
// reversed, never logged.
func hashIdentifier(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
