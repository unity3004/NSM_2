package util

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidPolicyPattern is the sentinel every policy path-pattern
// validation failure wraps — the policy-pattern counterpart to
// ErrInvalidSecretPath, kept as its own sentinel (not reused) so a caller
// can tell "this secret's own path is malformed" apart from "this
// policy's path pattern is malformed" without inspecting message text.
var ErrInvalidPolicyPattern = errors.New("invalid secret policy path pattern")

// wildcardSuffix is the only wildcard syntax a policy path pattern may
// contain: a literal "/*" at the very end, meaning "this prefix and
// everything under it." There is no support for a wildcard anywhere else
// in a pattern (no "prod/*/database", no "prod/db*") — see
// ValidatePolicyPathPattern's own doc comment for why restricting wildcard
// placement to exactly one shape is a deliberate anti-ambiguity choice,
// not a missing feature.
const wildcardSuffix = "/*"

// matchAllPattern is the one pattern that is itself entirely a wildcard —
// "*" alone, matching every canonical secret path. Distinct from
// "<prefix>/*" (which requires a non-empty prefix) so an administrator
// who genuinely wants "grant this role access to everything" writes an
// unambiguous, impossible-to-mistype-into single character, not an empty
// prefix before "/*" that could otherwise look like a typo.
const matchAllPattern = "*"

// NormalizePolicyPathPattern is policy patterns' analogue of
// NormalizeSecretPath — the same whitespace/leading-slash/trailing-slash
// canonicalization, applied to whichever part of the pattern isn't the
// wildcard marker itself, so "/dev/*" and "dev/*" (and " dev/* ") are
// stored and matched identically. Call this, then ValidatePolicyPathPattern,
// before a pattern is ever persisted or evaluated — the same
// normalize-then-validate order every secret path in this codebase already
// follows.
func NormalizePolicyPathPattern(pattern string) string {
	trimmed := strings.TrimSpace(pattern)
	if trimmed == matchAllPattern {
		return matchAllPattern
	}
	if base, ok := strings.CutSuffix(trimmed, wildcardSuffix); ok {
		normalizedBase := NormalizeSecretPath(base)
		if normalizedBase == "" {
			// "/*" or "*/" with nothing meaningful before the wildcard —
			// collapses to the explicit match-all form rather than a
			// degenerate "/*" pattern that would otherwise need its own
			// special-cased matching rule.
			return matchAllPattern
		}
		return normalizedBase + wildcardSuffix
	}
	return NormalizeSecretPath(trimmed)
}

// ValidatePolicyPathPattern rejects everything a policy path pattern must
// never be. Call NormalizePolicyPathPattern first; this does not trim
// anything itself.
//
// Exactly two pattern shapes are accepted:
//   - "*" — matches every canonical secret path.
//   - "<path>/*" — matches every canonical secret path that starts with
//     <path> + "/". <path> itself must be a valid secret path (see
//     ValidateSecretPath) — this is what guarantees a policy pattern's
//     non-wildcard portion follows the exact same character/segment/
//     traversal rules as a real secret path, the "one canonical
//     normalization strategy" requirement: there is no second, looser set
//     of rules for what characters a policy pattern's prefix may contain.
//   - Anything else (no wildcard at all) is an exact-match pattern,
//     itself required to be a valid secret path.
//
// A "*" may only appear as the entire pattern or as the final "/*"
// segment — never embedded mid-pattern ("prod/*/database") and never as
// a partial-segment glob ("prod/db*"). Both of those shapes would make
// matching ambiguous in exactly the way this package's own MatchPolicyPathPattern
// is designed to never be: "does prod/db* match prod/database or only
// prod/db-something"? is a question this codebase never has to answer
// because the syntax that would raise it is rejected here, before a
// pattern is ever stored.
func ValidatePolicyPathPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("%w: must not be empty", ErrInvalidPolicyPattern)
	}
	if pattern == matchAllPattern {
		return nil
	}
	if base, ok := strings.CutSuffix(pattern, wildcardSuffix); ok {
		if base == "" {
			return fmt.Errorf(`%w: a wildcard pattern must have a non-empty prefix before "/*" — use "*" to match every path`, ErrInvalidPolicyPattern)
		}
		if strings.Contains(base, matchAllPattern) {
			return fmt.Errorf(`%w: "*" is only allowed as the entire pattern or as a trailing "/*" segment`, ErrInvalidPolicyPattern)
		}
		if err := ValidateSecretPath(base); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidPolicyPattern, err)
		}
		return nil
	}
	if strings.Contains(pattern, matchAllPattern) {
		return fmt.Errorf(`%w: "*" is only allowed as the entire pattern or as a trailing "/*" segment`, ErrInvalidPolicyPattern)
	}
	if err := ValidateSecretPath(pattern); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidPolicyPattern, err)
	}
	return nil
}

// MatchPolicyPathPattern reports whether pattern (already normalized and
// validated) applies to canonicalPath (already normalized via
// NormalizeSecretPath — this function does not normalize its input,
// callers must have already done so, exactly like every other function in
// this file).
//
// Matching rules, explicitly:
//   - "*" matches every path.
//   - "<prefix>/*" matches canonicalPath if and only if canonicalPath
//     starts with "<prefix>/" — note the trailing slash IS part of the
//     comparison. "<prefix>/*" deliberately does NOT match "<prefix>"
//     itself (a policy on "dev/*" grants access to things inside dev/,
//     not to a secret that happens to be named exactly "dev" — that would
//     need its own exact-match pattern) and does NOT match a sibling path
//     that merely shares the same string prefix without a "/" boundary:
//     "prod/db/*" matches "prod/db/password" but never "prod/database",
//     because "prod/database" does not start with "prod/db/". This is
//     the prefix-boundary correctness the objective calls out by name —
//     a naive strings.HasPrefix(canonicalPath, prefix) without the
//     trailing "/" would incorrectly match "prod/database" against a
//     "prod/db" -shaped pattern, exactly the bypass this function exists
//     to prevent.
//   - Anything else is an exact-match pattern: matches canonicalPath if
//     and only if the two strings are identical. Matching is
//     case-sensitive, the same deliberate choice NormalizeSecretPath's own
//     doc comment makes for secret paths themselves (path casing is
//     meaningful, user-chosen structure, not normalized away).
func MatchPolicyPathPattern(pattern, canonicalPath string) bool {
	if pattern == matchAllPattern {
		return true
	}
	if prefix, ok := strings.CutSuffix(pattern, wildcardSuffix); ok {
		return strings.HasPrefix(canonicalPath, prefix+"/")
	}
	return pattern == canonicalPath
}
