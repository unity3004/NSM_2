package util

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidSecretPath is the sentinel every path-validation failure wraps,
// mirroring entity's sentinel-error convention (see entity/errors.go) even
// though this lives in util: nothing below internal/service exists yet to
// own it (no DTO layer this phase — see migrations/000024's own doc
// comment), and callers can still errors.Is against it once one does.
var ErrInvalidSecretPath = errors.New("invalid secret path")

// MaxSecretPathLength matches secrets.ck_secrets_path_not_empty's own upper
// bound (migrations/000024) — validating it here means a bad path is
// rejected with a clear message before it ever reaches that constraint,
// the same "DB CHECK is defense-in-depth, not the primary validation"
// split RegisterRequest.Validate() already uses for email.
const MaxSecretPathLength = 1024

// secretPathCharPattern is deliberately narrow: letters, digits, and
// '.', '_', '-' within a segment, '/' as the only segment separator. No
// spaces, no unicode, no shell/URL metacharacters — a secret path is an
// identifier, not free text, and every character allowed here is safe to
// place unescaped into a URL path segment or a log line.
var secretPathCharPattern = regexp.MustCompile(`^[A-Za-z0-9._\-/]+$`)

// NormalizeSecretPath trims surrounding whitespace and any leading/trailing
// '/' before a path is validated or stored — "/prod/db/" and "prod/db" are
// the same secret, and the stored form should always be the one without
// the redundant slashes, the same write-time-canonicalization reasoning
// NormalizeEmail already applies (see that function's own doc comment).
// It does NOT lowercase: unlike email, a secret path's casing is
// meaningful, user-chosen structure (e.g. "API-Keys" vs "api-keys" as
// distinct naming conventions different teams use), so case-insensitive
// *uniqueness* is left entirely to secrets.path's CITEXT column type
// rather than forced at write time.
func NormalizeSecretPath(path string) string {
	return strings.Trim(strings.TrimSpace(path), "/")
}

// ValidateSecretPath rejects everything a secret path must never be: empty,
// too long, containing characters outside secretPathCharPattern, containing
// an empty segment (a stray "//"), or containing a "." or ".." segment —
// the last of which is a path-traversal guard: nothing downstream ever
// resolves a secret path against a filesystem, but ".." segments in a
// hierarchical identifier are a well-known way to later confuse whatever
// eventually does list/prefix-match against it (a future List-by-prefix
// endpoint, an on-disk cache), so it is rejected here before it can ever be
// stored. Call NormalizeSecretPath first; this does not trim anything
// itself.
func ValidateSecretPath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: must not be empty", ErrInvalidSecretPath)
	}
	if len(path) > MaxSecretPathLength {
		return fmt.Errorf("%w: must be at most %d characters", ErrInvalidSecretPath, MaxSecretPathLength)
	}
	if !secretPathCharPattern.MatchString(path) {
		return fmt.Errorf("%w: may only contain letters, digits, '.', '_', '-', and '/' as a segment separator", ErrInvalidSecretPath)
	}
	for segment := range strings.SplitSeq(path, "/") {
		switch segment {
		case "":
			return fmt.Errorf("%w: must not contain an empty segment ('//')", ErrInvalidSecretPath)
		case ".", "..":
			return fmt.Errorf("%w: must not contain a '.' or '..' segment", ErrInvalidSecretPath)
		}
	}
	return nil
}
