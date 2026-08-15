package security

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestTokenService(t *testing.T, issuer string, ttl time.Duration) (*TokenService, *SigningKeySet) {
	t.Helper()
	keys, err := LoadSigningKeySet("test-key-1", generateEd25519PrivateKeyPEM(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	return NewTokenService(keys, issuer, ttl), keys
}

func decodeHeader(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q does not have 3 parts", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return header
}

// rawEdDSAToken hand-signs an arbitrary header/payload with the real
// Ed25519 private key, bypassing jwt.NewWithClaims entirely — the only
// way to construct a token with a genuinely valid signature but claims
// (or a header) the library's own claims type would never produce, which
// is exactly what proving ValidateAccessToken's own extra checks (missing
// sub, missing jti) actually run requires: a signature failure would
// otherwise be indistinguishable from those checks doing their job.
func rawEdDSAToken(t *testing.T, keys *SigningKeySet, header, payload map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	encode := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signingInput := encode(h) + "." + encode(p)
	sig := ed25519.Sign(keys.PrivateKey, []byte(signingInput))
	return signingInput + "." + encode(sig)
}

func validClaims(issuer, audience string, now time.Time) map[string]any {
	return map[string]any{
		"iss": issuer,
		"sub": "user-1",
		"aud": []string{audience},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"jti": "test-jti-1",
	}
}

// --- creation ---

func TestTokenService_CreateAccessToken_Success(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", 10*time.Minute)

	token, err := svc.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v, want nil", err)
	}
	if token == "" {
		t.Fatal("CreateAccessToken() returned an empty token")
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Errorf("token has %d dot-separated parts, want 3", len(parts))
	}
}

func TestTokenService_CreateAccessToken_MissingSubject(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", 10*time.Minute)
	if _, err := svc.CreateAccessToken("", "billing-api", "session-1"); !errors.Is(err, ErrMissingSubject) {
		t.Errorf("CreateAccessToken() with no subject, error = %v, want ErrMissingSubject", err)
	}
}

func TestTokenService_CreateAccessToken_MissingAudience(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", 10*time.Minute)
	if _, err := svc.CreateAccessToken("user-1", "", "session-1"); !errors.Is(err, ErrMissingAudience) {
		t.Errorf("CreateAccessToken() with no audience, error = %v, want ErrMissingAudience", err)
	}
}

// TestTokenService_CreateAccessToken_SessionIDOptional proves sessionID,
// unlike subject and audience, is never required — an empty value is
// accepted (never ErrMissingSubject/ErrMissingAudience's sibling), the
// token still validates, and ValidateAccessToken reports SessionID back
// as "", matching AccessTokenClaims' own omitempty contract for a token
// that legitimately has no session to name.
func TestTokenService_CreateAccessToken_SessionIDOptional(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", 10*time.Minute)

	token, err := svc.CreateAccessToken("user-1", "billing-api", "")
	if err != nil {
		t.Fatalf("CreateAccessToken() with no session ID, error = %v, want nil", err)
	}
	claims, err := svc.ValidateAccessToken(token, "billing-api")
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v, want nil", err)
	}
	if claims.SessionID != "" {
		t.Errorf("SessionID = %q, want empty", claims.SessionID)
	}
}

// TestTokenService_CreateAccessToken_JTIUniqueAcrossTokens generates many
// tokens and proves jti is present and never repeats — the "unpredictable,
// not sequential" requirement, proven the same way
// TestSessionService_CreateSession_TokenIsRandomAndUnique proved it for
// session tokens in Milestone 4B.
func TestTokenService_CreateAccessToken_JTIUniqueAcrossTokens(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", 10*time.Minute)

	const attempts = 50
	seen := make(map[string]bool, attempts)
	for i := 0; i < attempts; i++ {
		token, err := svc.CreateAccessToken("user-1", "billing-api", "session-1")
		if err != nil {
			t.Fatalf("CreateAccessToken() error = %v", err)
		}
		claims, err := svc.ValidateAccessToken(token, "billing-api")
		if err != nil {
			t.Fatalf("ValidateAccessToken() error = %v", err)
		}
		if claims.ID == "" {
			t.Fatal("claims.ID (jti) is empty")
		}
		if seen[claims.ID] {
			t.Fatalf("jti %q was generated twice across %d attempts", claims.ID, attempts)
		}
		seen[claims.ID] = true
	}
}

// TestTokenService_CreateAccessToken_KIDPresent proves the token header
// carries kid — required for key rotation to work at all, since it's what
// a verifier's key lookup keys on.
func TestTokenService_CreateAccessToken_KIDPresent(t *testing.T) {
	svc, keys := newTestTokenService(t, "auth-service", 10*time.Minute)
	token, err := svc.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	header := decodeHeader(t, token)
	kid, _ := header["kid"].(string)
	if kid == "" {
		t.Fatal("token header has no kid")
	}
	if kid != keys.CurrentKeyID {
		t.Errorf("header kid = %q, want %q", kid, keys.CurrentKeyID)
	}
}

// TestTokenService_CreateAccessToken_NeverLeaksPrivateKey checks the
// token itself and every error CreateAccessToken can return for the raw
// private key material — a JWT's signature is a function of the private
// key, not a copy of it, but this is asserted directly rather than
// assumed.
func TestTokenService_CreateAccessToken_NeverLeaksPrivateKey(t *testing.T) {
	svc, keys := newTestTokenService(t, "auth-service", 10*time.Minute)
	privB64 := base64.RawStdEncoding.EncodeToString(keys.PrivateKey)

	token, err := svc.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}
	if strings.Contains(token, privB64) {
		t.Error("created token contains the raw private key")
	}

	_, err = svc.CreateAccessToken("", "billing-api", "session-1")
	if err != nil && strings.Contains(err.Error(), privB64) {
		t.Errorf("error message leaked the private key: %v", err)
	}
}

// --- validation: happy path and claim correctness ---

func TestTokenService_ValidateAccessToken_Success(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", 10*time.Minute)
	before := time.Now()

	token, err := svc.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}
	claims, err := svc.ValidateAccessToken(token, "billing-api")
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v, want nil", err)
	}

	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-1")
	}
	if claims.SessionID != "session-1" {
		t.Errorf("SessionID = %q, want %q", claims.SessionID, "session-1")
	}
	if claims.Issuer != "auth-service" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "auth-service")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "billing-api" {
		t.Errorf("Audience = %v, want [%q]", claims.Audience, "billing-api")
	}
	if claims.ID == "" {
		t.Error("ID (jti) is empty")
	}
	if claims.IssuedAt == nil || claims.IssuedAt.Time.Before(before.Add(-time.Second)) {
		t.Errorf("IssuedAt = %v, want it close to %v", claims.IssuedAt, before)
	}
	wantExpiry := before.Add(10 * time.Minute)
	if claims.ExpiresAt == nil || claims.ExpiresAt.Time.Before(wantExpiry.Add(-5*time.Second)) || claims.ExpiresAt.Time.After(wantExpiry.Add(5*time.Second)) {
		t.Errorf("ExpiresAt = %v, want it close to %v (10m TTL)", claims.ExpiresAt, wantExpiry)
	}
}

// --- validation: rejections ---

func TestTokenService_ValidateAccessToken_WrongSigningKey(t *testing.T) {
	svcA, keysA := newTestTokenService(t, "auth-service", time.Hour)
	token, err := svcA.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	// A verifier whose key store maps the *same* kid to different key
	// material — simulating a misconfigured or compromised key store, or
	// simply an attacker without the real private key. Reusing keysA's
	// own kid is deliberate: this must fail on cryptographic grounds, not
	// because the kid lookup itself missed.
	otherKeys, err := LoadSigningKeySet(keysA.CurrentKeyID, generateEd25519PrivateKeyPEM(t), "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet: %v", err)
	}
	svcB := NewTokenService(otherKeys, "auth-service", time.Hour)

	if _, err := svcB.ValidateAccessToken(token, "billing-api"); err == nil {
		t.Fatal("ValidateAccessToken() with the wrong signing key = nil error, want one")
	}
}

func TestTokenService_ValidateAccessToken_WrongIssuer(t *testing.T) {
	svcA, keys := newTestTokenService(t, "auth-service", time.Hour)
	token, err := svcA.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	svcB := NewTokenService(keys, "some-other-issuer", time.Hour)
	if _, err := svcB.ValidateAccessToken(token, "billing-api"); !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		t.Errorf("ValidateAccessToken() with a mismatched issuer, error = %v, want jwt.ErrTokenInvalidIssuer", err)
	}
}

func TestTokenService_ValidateAccessToken_WrongAudience(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", time.Hour)
	token, err := svc.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	if _, err := svc.ValidateAccessToken(token, "some-other-api"); !errors.Is(err, jwt.ErrTokenInvalidAudience) {
		t.Errorf("ValidateAccessToken() with a mismatched audience, error = %v, want jwt.ErrTokenInvalidAudience", err)
	}
}

func TestTokenService_ValidateAccessToken_Expired(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", -time.Minute)
	token, err := svc.CreateAccessToken("user-1", "billing-api", "session-1")
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	if _, err := svc.ValidateAccessToken(token, "billing-api"); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("ValidateAccessToken() on an expired token, error = %v, want jwt.ErrTokenExpired", err)
	}
}

func TestTokenService_ValidateAccessToken_MissingSubject(t *testing.T) {
	svc, keys := newTestTokenService(t, "auth-service", time.Hour)
	now := time.Now()
	payload := validClaims("auth-service", "billing-api", now)
	delete(payload, "sub")
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": keys.CurrentKeyID}
	token := rawEdDSAToken(t, keys, header, payload)

	if _, err := svc.ValidateAccessToken(token, "billing-api"); !errors.Is(err, ErrMissingSubject) {
		t.Errorf("ValidateAccessToken() with no sub claim, error = %v, want ErrMissingSubject", err)
	}
}

func TestTokenService_ValidateAccessToken_MissingJTI(t *testing.T) {
	svc, keys := newTestTokenService(t, "auth-service", time.Hour)
	now := time.Now()
	payload := validClaims("auth-service", "billing-api", now)
	delete(payload, "jti")
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": keys.CurrentKeyID}
	token := rawEdDSAToken(t, keys, header, payload)

	if _, err := svc.ValidateAccessToken(token, "billing-api"); !errors.Is(err, ErrMissingTokenID) {
		t.Errorf("ValidateAccessToken() with no jti claim, error = %v, want ErrMissingTokenID", err)
	}
}

// TestTokenService_ValidateAccessToken_UnsupportedAlgorithm_None is the
// classic "alg: none" attack: a token that claims to need no signature at
// all. jwt.WithValidMethods must reject it purely on the header, before
// any key lookup or signature check.
func TestTokenService_ValidateAccessToken_UnsupportedAlgorithm_None(t *testing.T) {
	svc, keys := newTestTokenService(t, "auth-service", time.Hour)
	now := time.Now()
	header := map[string]any{"alg": "none", "typ": "JWT", "kid": keys.CurrentKeyID}
	payload := validClaims("auth-service", "billing-api", now)
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	encode := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	token := encode(h) + "." + encode(p) + "." // empty signature segment

	if _, err := svc.ValidateAccessToken(token, "billing-api"); err == nil {
		t.Fatal("ValidateAccessToken() on an alg:none token = nil error, want one")
	}
}

// TestTokenService_ValidateAccessToken_AlgorithmConfusionDowngrade is the
// downgrade attack this milestone explicitly calls out: a token whose
// header claims HS256, HMAC-signed using this service's own *public* Ed25519
// key bytes as the shared secret — the exact trick that succeeds against
// a Keyfunc that hands back a key without checking what token.Method
// actually is. jwt.WithValidMethods must reject it before keyFunc's own
// defense-in-depth check would even get a chance to.
func TestTokenService_ValidateAccessToken_AlgorithmConfusionDowngrade(t *testing.T) {
	svc, keys := newTestTokenService(t, "auth-service", time.Hour)
	now := time.Now()
	header := map[string]any{"alg": "HS256", "typ": "JWT", "kid": keys.CurrentKeyID}
	payload := validClaims("auth-service", "billing-api", now)
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	encode := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signingInput := encode(h) + "." + encode(p)

	pub := keys.PublicKeys[keys.CurrentKeyID]
	mac := hmac.New(sha256.New, pub)
	mac.Write([]byte(signingInput))
	token := signingInput + "." + encode(mac.Sum(nil))

	if _, err := svc.ValidateAccessToken(token, "billing-api"); err == nil {
		t.Fatal("ValidateAccessToken() on an HS256-downgraded token = nil error, want one")
	}
}

func TestTokenService_ValidateAccessToken_MalformedJWT(t *testing.T) {
	svc, _ := newTestTokenService(t, "auth-service", time.Hour)

	for _, malformed := range []string{"", "not-a-jwt", "only.two-parts", "a.b.c.d"} {
		if _, err := svc.ValidateAccessToken(malformed, "billing-api"); err == nil {
			t.Errorf("ValidateAccessToken(%q) = nil error, want one", malformed)
		}
	}
}
