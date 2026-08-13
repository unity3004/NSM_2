package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrInvalidToken covers every way a bearer token can fail to verify —
// bad signature, malformed structure, wrong algorithm — collapsed into one
// error so a caller can't accidentally build different behavior around
// "signature bad" vs. "token garbled" (an attacker-observable difference
// that should not exist).
var ErrInvalidToken = errors.New("invalid or expired access token")

// Claims is the JWT payload this service issues. It carries just enough to
// authorize a request without a database round trip per call — the access
// token's whole reason to exist alongside the session/refresh-token pair.
type Claims struct {
	Subject        string   `json:"sub"` // entity.User.ID or entity.ServiceAccount.ID
	OrganizationID string   `json:"org_id"`
	SessionID      string   `json:"sid,omitempty"`   // absent for service-account tokens
	Permissions    []string `json:"perms,omitempty"` // resource:action strings, pre-resolved at issuance
	IssuedAt       int64    `json:"iat"`
	ExpiresAt      int64    `json:"exp"`
}

// ExpiresAtTime is a convenience accessor — JWT numeric dates are Unix
// seconds, which is a detail middleware.Auth shouldn't have to know.
func (c Claims) ExpiresAtTime() time.Time { return time.Unix(c.ExpiresAt, 0) }

// IsServiceAccount reports whether this token identifies a machine
// principal (entity.ServiceAccount) rather than a human one
// (entity.User) — the single, centralized place that inference is made,
// backed by SessionID's own doc comment above ("absent for
// service-account tokens"): every human login path
// (AuthService.issueSession, RefreshTokenService.Refresh) always sets a
// real session ID, and ServiceAccountService.Authenticate — the only
// other place Sign is ever called — never does, by construction, because
// a service account has no session in the human sense. Every caller that
// needs to branch RBAC/audit/rate-limit behavior on identity type
// (middleware.RequirePermission, middleware.RateLimit's own
// requestIdentity, SecretService/SecretPolicyService) goes through this
// method rather than re-deriving the same "SessionID == \"\"" check
// independently, so the one signal this token format uses to carry
// identity type can never drift out of sync with itself.
func (c Claims) IsServiceAccount() bool { return c.SessionID == "" }

// JWTSigner issues and verifies HS256-signed access tokens. HMAC-SHA256 is
// a deliberate, minimal choice: it needs nothing beyond crypto/hmac and
// crypto/sha256 from the standard library, so the service's only two
// external dependencies stay bcrypt and the Postgres driver (see go.mod).
// A larger deployment with multiple services validating tokens
// independently would switch this to RS256/ES256 so only the issuer holds
// the signing key — noted here rather than built, since this service is
// both issuer and sole verifier today.
type JWTSigner struct {
	key       []byte
	accessTTL time.Duration
}

func NewJWTSigner(signingKey string, accessTTL time.Duration) *JWTSigner {
	return &JWTSigner{key: []byte(signingKey), accessTTL: accessTTL}
}

func (s *JWTSigner) AccessTTL() time.Duration { return s.accessTTL }

// Sign issues a token for the given subject, valid for AccessTTL from now.
func (s *JWTSigner) Sign(subject, organizationID, sessionID string, permissions []string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(s.accessTTL)
	claims := Claims{
		Subject:        subject,
		OrganizationID: organizationID,
		SessionID:      sessionID,
		Permissions:    permissions,
		IssuedAt:       now.Unix(),
		ExpiresAt:      exp.Unix(),
	}
	token, err := s.encode(claims)
	return token, exp, err
}

func (s *JWTSigner) encode(claims Claims) (string, error) {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64URLEncode(payloadBytes)
	signingInput := header + "." + payload
	sig := s.sign(signingInput)
	return signingInput + "." + sig, nil
}

func (s *JWTSigner) sign(signingInput string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(signingInput))
	return base64URLEncode(mac.Sum(nil))
}

// Verify checks the signature and expiry and returns the decoded Claims.
func (s *JWTSigner) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	expectedSig := s.sign(signingInput)
	if subtle.ConstantTimeCompare([]byte(expectedSig), []byte(parts[2])) != 1 {
		return nil, ErrInvalidToken
	}
	payloadBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}
	if time.Now().After(claims.ExpiresAtTime()) {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
