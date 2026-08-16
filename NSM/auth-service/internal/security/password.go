// Package security provides password-hashing primitives for the
// authentication service — specifically Argon2id, per the Sprint 2
// architecture design (see auth-architecture-sprint2.md §7, control C2).
//
// This package is deliberately narrow and self-contained: it knows how to
// turn a plaintext password into a verifiable, storable hash and back,
// and nothing else. It has no dependency on internal/entity,
// internal/repository, any logging package, net/http, or a database
// driver. That absence is a security property, not an oversight — a
// package that imports no logger cannot be made to log a password by a
// future one-line edit; see the package's design notes for why that
// matters more than a code-review rule ever could.
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Sentinel errors. Every one is safe to propagate several layers up
// without revealing anything about the password or the hash's contents —
// each names a category of problem ("too long", "wrong format"), never
// the value that triggered it.
var (
	ErrEmptyPassword       = errors.New("security: password must not be empty")
	ErrPasswordTooLong     = errors.New("security: password exceeds maximum allowed length")
	ErrEmptyHash           = errors.New("security: encoded hash must not be empty")
	ErrInvalidHashFormat   = errors.New("security: encoded hash is not in a recognized format")
	ErrUnsupportedVariant  = errors.New("security: encoded hash uses an unsupported Argon2 variant")
	ErrIncompatibleVersion = errors.New("security: encoded hash uses an incompatible Argon2 version")
)

// maxPasswordLength bounds Hash and Verify's input purely as a
// resource-exhaustion guard. Argon2id's cost is dominated by its
// memory/time parameters, not by password length, but an unbounded input
// is still an unbounded amount of data copied and hashed per request.
// No legitimate password approaches this bound; nothing above it is
// rejected for cryptographic reasons.
const maxPasswordLength = 256

// Decoded salt/hash byte-length bounds for decodeHash. No Params this
// package's own Hash ever produces comes close to these — DefaultParams
// uses 16 and 32 bytes respectively — but decodeHash parses untrusted
// input (a database column that could be corrupted or tampered with),
// and without an upper bound a value like a 10,000-byte salt parses as
// "syntactically fine" while forcing Argon2id to hash an attacker- or
// corruption-controlled amount of extra data. A lower bound catches the
// opposite problem: a salt or key so short it couldn't have come from
// this package's own random generation.
const (
	minSaltLength = 8
	maxSaltLength = 64
	minKeyLength  = 16
	maxKeyLength  = 128
)

// Params configures Argon2id's cost. See the package-level documentation
// ("what memory, time, and parallelism mean") for how to choose these —
// DefaultParams is a starting point to benchmark on real hardware, not a
// value to trust unconditionally on every deployment.
type Params struct {
	Memory      uint32 // KiB of memory used per hash operation
	Iterations  uint32 // number of passes over that memory
	Parallelism uint8  // number of parallel lanes/threads
	SaltLength  uint32 // bytes of random salt generated per hash
	KeyLength   uint32 // bytes of derived key (hash output) per hash
}

// DefaultParams targets roughly 250-400ms per hash on a modern
// server-class CPU core with 64 MiB available for this operation alone.
// Re-benchmark on the actual production host before trusting this
// number — see Params' doc comment.
var DefaultParams = Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// validate rejects parameter combinations that are nonsensical or that
// could make the underlying argon2 implementation behave unpredictably
// (a zero parallelism or iteration count). This runs both on
// caller-supplied Params (a programming-error defense) and on Params
// parsed out of a stored hash (a corrupted-data defense) — the same
// bar applies regardless of where the values came from.
func (p Params) validate() error {
	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return ErrInvalidHashFormat
	}
	// The Argon2 specification itself requires at least 8*parallelism KiB
	// of memory; below that the algorithm's own guarantees don't hold.
	if p.Memory < 8*uint32(p.Parallelism) {
		return ErrInvalidHashFormat
	}
	return nil
}

// PasswordService hashes and verifies passwords using Argon2id. It holds
// no mutable state beyond its immutable configured Params, so a single
// instance is safe for concurrent use by multiple goroutines.
type PasswordService struct {
	params Params
}

// NewPasswordService constructs a PasswordService with the given
// parameters. Pass DefaultParams unless a specific deployment has
// benchmarked and deliberately chosen different values.
func NewPasswordService(params Params) *PasswordService {
	return &PasswordService{params: params}
}

// Hash derives an Argon2id hash of password using the service's
// configured Params and a freshly generated random salt, returning it
// encoded as a single self-describing string:
//
//	$argon2id$v=19$m=65536,t=3,p=4$<base64 salt>$<base64 hash>
//
// This is the standard reference Argon2id encoding — not a format
// invented for this package — so every parameter needed to verify the
// hash later travels with it, and the string is recognizable on sight to
// anyone who has seen an Argon2id hash before.
//
// The caller must never log password — see the package doc comment.
func (s *PasswordService) Hash(password string) (string, error) {
	if err := validatePasswordInput(password); err != nil {
		return "", err
	}
	if err := s.params.validate(); err != nil {
		return "", fmt.Errorf("security: service configured with invalid params: %w", err)
	}

	salt := make([]byte, s.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		// crypto/rand failing means the OS entropy source itself is
		// broken — there is nothing password-specific to add here, and
		// nothing safe to retry into.
		return "", fmt.Errorf("security: generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, s.params.Iterations, s.params.Memory, s.params.Parallelism, s.params.KeyLength)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		s.params.Memory, s.params.Iterations, s.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// Verify reports whether password matches encodedHash.
//
// The Argon2id parameters used to recompute the hash are read from
// encodedHash itself, never from this service's configured Params — a
// hash created under an older, weaker configuration must go on verifying
// correctly after the service's defaults are strengthened for *new*
// hashes. Migrating an individual stored hash to stronger parameters
// (rehash-on-successful-login) is deliberately the caller's
// responsibility, not this method's: Verify only ever checks, it never
// rewrites anything.
//
// A (false, nil) result means the password was checked and did not
// match — an expected, non-exceptional outcome, not an error. A non-nil
// error means verification could not be attempted at all, because
// encodedHash is empty or malformed. Callers that expose either outcome
// to an end user should collapse both into one generic response (see
// auth-architecture-sprint2.md §7, control C6) — that collapsing belongs
// at the caller's boundary, not here, because an internal caller (e.g.
// anomaly-detection logging) legitimately needs the distinction even
// though an HTTP response must not.
func (s *PasswordService) Verify(password, encodedHash string) (bool, error) {
	if err := validatePasswordInput(password); err != nil {
		return false, err
	}
	if encodedHash == "" {
		return false, ErrEmptyHash
	}

	params, salt, storedHash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	computedHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(storedHash)))

	// subtle.ConstantTimeCompare, never bytes.Equal and never a manual
	// byte-by-byte loop: a short-circuiting comparison leaks, via timing,
	// how many leading bytes matched. That's irrelevant to the hash's own
	// preimage resistance, but there's no reason to accept any timing
	// signal here when a constant-time comparison costs nothing extra.
	match := subtle.ConstantTimeCompare(storedHash, computedHash) == 1
	return match, nil
}

func validatePasswordInput(password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	if len(password) > maxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}

// decodeHash parses the reference Argon2id encoding Hash produces,
// rejecting anything that doesn't match it exactly rather than trying to
// be lenient. A permissive parser here would mean a corrupted or
// tampered database column could silently verify under attacker-chosen
// parameters instead of failing loudly and visibly.
func decodeHash(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, ErrInvalidHashFormat
	}

	if parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrUnsupportedVariant
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, ErrInvalidHashFormat
	}
	if version != argon2.Version {
		return Params{}, nil, nil, ErrIncompatibleVersion
	}

	var params Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return Params{}, nil, nil, ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < minSaltLength || len(salt) > maxSaltLength {
		return Params{}, nil, nil, ErrInvalidHashFormat
	}
	params.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) < minKeyLength || len(hash) > maxKeyLength {
		return Params{}, nil, nil, ErrInvalidHashFormat
	}
	params.KeyLength = uint32(len(hash))

	if err := params.validate(); err != nil {
		return Params{}, nil, nil, err
	}

	return params, salt, hash, nil
}
