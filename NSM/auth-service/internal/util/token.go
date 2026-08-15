package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// NewOpaqueToken generates a random, high-entropy secret suitable for a
// session token or refresh token — the raw value handed to the client.
// Only HashToken's output of it is ever persisted (sessions.session_token_hash,
// refresh_tokens.token_hash); the raw value itself lives nowhere but the
// client and the HTTP response that issued it.
func NewOpaqueToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// HashToken returns a deterministic SHA-256 hex digest of a raw token, for
// storage and for equality lookups (`WHERE token_hash = $1`) — a lookup a
// bcrypt-style salted hash could never support, which is why session and
// refresh tokens use this instead of HashPassword.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// NewAPIKey generates a long-lived API key in `sk_live_<random>` form and
// returns both the full raw secret (shown to the caller exactly once) and
// its short, non-secret prefix (stored alongside the hash for display —
// see entity.APIKey.KeyPrefix).
func NewAPIKey() (secret, prefix string, err error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	random := base64.RawURLEncoding.EncodeToString(b[:])
	secret = "sk_live_" + random
	prefix = secret[:12]
	return secret, prefix, nil
}
