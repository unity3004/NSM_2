package security

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors for the checks golang-jwt/jwt/v5 doesn't perform on its
// own. Everything the library *does* check — bad signature, wrong issuer,
// wrong audience, expired, malformed structure — is reported via its own
// jwt.ErrToken* sentinels, propagated through errors.Is-compatible
// wrapping rather than reinvented here.
var (
	ErrMissingAudience      = errors.New("security: audience is required")
	ErrMissingSubject       = errors.New("security: access token is missing a required subject (sub) claim")
	ErrMissingTokenID       = errors.New("security: access token is missing a required token identifier (jti) claim")
	ErrInvalidIssuedAt      = errors.New("security: access token has a missing or implausible issued-at (iat) claim")
	ErrUnsupportedAlgorithm = errors.New("security: access token uses an unsupported signing algorithm")
	ErrUnknownSigningKey    = errors.New("security: access token references an unknown or missing key ID (kid)")
)

// clockSkewAllowance bounds how far in the future an iat may legitimately
// be — accommodating minor clock drift between the machine that issued a
// token and the one validating it, without accepting a token that claims
// to have been issued minutes or hours from now.
const clockSkewAllowance = 5 * time.Second

// AccessTokenClaims carries exactly the registered claims Milestone 5A
// requires — iss, sub, aud, iat, exp, jti — nothing else. Unlike
// util.Claims (the existing HS256 implementation's payload; see this
// milestone's report on why that implementation is untouched), it
// deliberately carries no organization ID, session ID, or permissions:
// this milestone's required claim list is exhaustive, not a floor.
type AccessTokenClaims struct {
	jwt.RegisteredClaims
}

// TokenService issues and validates short-lived, Ed25519-signed
// (EdDSA / RFC 8037) access tokens. It holds the private signing key
// (requirement #3, "the authentication service must hold the private
// signing key"); a future verification-only service would instead
// construct a SigningKeySet with only PublicKeys populated and PrivateKey
// left nil (requirement #4) — CreateAccessToken would simply fail the
// first time it tried to sign with a zero-value key, which is the correct
// failure mode for a service that was never supposed to mint tokens.
type TokenService struct {
	keys   *SigningKeySet
	issuer string
	ttl    time.Duration
}

// NewTokenService constructs a TokenService. ttl is every access token's
// fixed lifetime — there is deliberately no per-call override anywhere in
// this type's API, so nothing downstream can ever request a longer-lived
// token than the service's own configuration allows.
func NewTokenService(keys *SigningKeySet, issuer string, ttl time.Duration) *TokenService {
	return &TokenService{keys: keys, issuer: issuer, ttl: ttl}
}

// CreateAccessToken issues a new access token asserting subject as `sub`
// and audience as `aud`, signed with the current signing key. subject is
// a stable user or service-account identity ID (entity.User.ID /
// entity.ServiceAccount.ID); audience is the API/service this token is
// intended for. Neither may be empty: an unaddressed or subjectless token
// is never a legitimate thing to mint.
func (s *TokenService) CreateAccessToken(subject, audience string) (string, error) {
	if subject == "" {
		return "", ErrMissingSubject
	}
	if audience == "" {
		return "", ErrMissingAudience
	}

	jti, err := newTokenID()
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := AccessTokenClaims{jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		ID:        jti,
	}}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	// The kid header is what lets a verifier — and ValidateAccessToken's
	// own keyFunc below — pick the right public key out of a set that may
	// hold more than one during a rotation window, without needing to try
	// every key it knows about.
	token.Header["kid"] = s.keys.CurrentKeyID

	signed, err := token.SignedString(s.keys.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("security: signing access token: %w", err)
	}
	return signed, nil
}

// ValidateAccessToken parses and fully validates tokenString, returning
// its claims only if every check below passes. expectedAudience is the
// caller's own identity — the API this code is running as — so a token
// minted for a different downstream service is rejected here rather than
// trusted just because it carries a valid signature from this issuer.
//
// Checked: well-formed JWT structure; signing algorithm is exactly EdDSA
// (jwt.WithValidMethods, plus an explicit type check inside keyFunc — see
// that method's comment for why both); signature, against the key named
// by the token's own kid header; issuer; audience; expiration (required —
// a token with no exp claim at all is rejected, never treated as
// non-expiring); issued-at (present and not implausibly future-dated);
// subject present; jti present. A token is never accepted on signature
// validity alone.
func (s *TokenService) ValidateAccessToken(tokenString, expectedAudience string) (*AccessTokenClaims, error) {
	if expectedAudience == "" {
		return nil, ErrMissingAudience
	}

	claims := &AccessTokenClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, s.keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	if claims.Subject == "" {
		return nil, ErrMissingSubject
	}
	if claims.ID == "" {
		return nil, ErrMissingTokenID
	}
	if claims.IssuedAt == nil || claims.IssuedAt.Time.After(time.Now().Add(clockSkewAllowance)) {
		return nil, ErrInvalidIssuedAt
	}
	return claims, nil
}

// keyFunc resolves the public key jwt.ParseWithClaims should verify
// against. jwt.WithValidMethods (in ValidateAccessToken above) already
// rejects any alg outside {"EdDSA"} by inspecting the token's header, but
// that option alone can't stop a Keyfunc that blindly trusts token.Method
// and hands back a key of the wrong kind for it — the classic
// algorithm-confusion vulnerability, where an attacker-chosen header is
// paired with a Keyfunc that never independently checks it. Re-asserting
// the concrete signing method here, inside the function that actually
// returns the verification key, is the second, independent half of that
// defense: belt and suspenders, deliberately, per this milestone's
// explicit requirement to never accept a token merely because *some*
// signature verifies.
func (s *TokenService) keyFunc(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, token.Header["alg"])
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, ErrUnknownSigningKey
	}
	pub, ok := s.keys.PublicKeys[kid]
	if !ok {
		return nil, ErrUnknownSigningKey
	}
	return pub, nil
}

// newTokenID generates jti: 16 bytes (128 bits) of crypto/rand entropy,
// base64url-encoded — unpredictable and non-sequential by construction,
// never a timestamp, counter, or anything else guessable. Implemented
// locally rather than via internal/util.NewUUID so this package keeps the
// same self-containment its own PasswordService already declares: no
// dependency on anything beyond the standard library and the one JWT
// module this milestone adds.
func newTokenID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("security: generating jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
