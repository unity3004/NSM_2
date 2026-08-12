package util

import (
	"errors"
	"testing"
)

// --- NormalizePolicyPathPattern ---

func TestNormalizePolicyPathPattern(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"already canonical exact path", "prod/database", "prod/database"},
		{"already canonical wildcard", "dev/*", "dev/*"},
		{"bare match-all", "*", "*"},
		{"whitespace trimmed", "  prod/database  ", "prod/database"},
		{"whitespace trimmed around wildcard", " dev/*  ", "dev/*"},
		{"leading slash stripped before wildcard", "/dev/*", "dev/*"},
		{"redundant slash before wildcard suffix collapsed", "dev//*", "dev/*"},
		{"leading/trailing slash on exact path", "/prod/database/", "prod/database"},
		{"wildcard with nothing meaningful before it collapses to match-all", "/*", "*"},
		{"wildcard with only slash before it collapses to match-all", "//*", "*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizePolicyPathPattern(tt.input); got != tt.want {
				t.Errorf("NormalizePolicyPathPattern(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- ValidatePolicyPathPattern ---

func TestValidatePolicyPathPattern_Valid(t *testing.T) {
	for _, pattern := range []string{"*", "dev/*", "prod/database", "prod/database/*", "dev/application/*", "a", "a/b/c"} {
		t.Run(pattern, func(t *testing.T) {
			if err := ValidatePolicyPathPattern(pattern); err != nil {
				t.Errorf("ValidatePolicyPathPattern(%q) = %v, want nil", pattern, err)
			}
		})
	}
}

func TestValidatePolicyPathPattern_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
	}{
		{"empty", ""},
		{"wildcard with empty prefix", "/*"}, // caller must normalize first — a raw "/*" is not itself one of the two accepted shapes
		{"embedded wildcard mid-pattern", "prod/*/database"},
		{"partial-segment glob", "prod/db*"},
		{"double wildcard suffix", "prod/**"},
		{"traversal in prefix", "prod/../etc"},
		{"dot segment in prefix", "prod/./database"},
		{"disallowed characters", "prod/db;DROP TABLE secrets"},
		{"empty segment", "prod//database"},
		{"traversal in wildcard prefix", "../etc/*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePolicyPathPattern(tt.pattern); err == nil {
				t.Errorf("ValidatePolicyPathPattern(%q) = nil, want an error", tt.pattern)
			} else if !errors.Is(err, ErrInvalidPolicyPattern) {
				t.Errorf("ValidatePolicyPathPattern(%q) error = %v, want it to wrap ErrInvalidPolicyPattern", tt.pattern, err)
			}
		})
	}
}

func TestNormalizeThenValidate_RealWorldInputs(t *testing.T) {
	// The pipeline every caller actually uses: normalize, then validate —
	// proving inputs a human admin would plausibly type all end up
	// accepted or rejected correctly after normalization, not just in
	// their already-canonical form.
	valid := []string{"/dev/*", " prod/database ", "/prod/database/", "*", " * "}
	for _, raw := range valid {
		t.Run("valid/"+raw, func(t *testing.T) {
			norm := NormalizePolicyPathPattern(raw)
			if err := ValidatePolicyPathPattern(norm); err != nil {
				t.Errorf("normalize(%q) = %q, ValidatePolicyPathPattern = %v, want nil", raw, norm, err)
			}
		})
	}
	invalid := []string{"../etc/*", "prod/../secret", "prod/*/database"}
	for _, raw := range invalid {
		t.Run("invalid/"+raw, func(t *testing.T) {
			norm := NormalizePolicyPathPattern(raw)
			if err := ValidatePolicyPathPattern(norm); err == nil {
				t.Errorf("normalize(%q) = %q, ValidatePolicyPathPattern = nil, want an error", raw, norm)
			}
		})
	}
}

// --- MatchPolicyPathPattern ---

func TestMatchPolicyPathPattern_MatchAll(t *testing.T) {
	for _, path := range []string{"a", "a/b", "prod/database/creds"} {
		if !MatchPolicyPathPattern("*", path) {
			t.Errorf(`MatchPolicyPathPattern("*", %q) = false, want true`, path)
		}
	}
}

func TestMatchPolicyPathPattern_ExactMatch(t *testing.T) {
	if !MatchPolicyPathPattern("prod/database", "prod/database") {
		t.Error("exact pattern should match the identical path")
	}
	if MatchPolicyPathPattern("prod/database", "prod/databases") {
		t.Error("exact pattern must not match a similarly-named path")
	}
	if MatchPolicyPathPattern("prod/database", "PROD/DATABASE") {
		t.Error("matching must be case-sensitive")
	}
}

func TestMatchPolicyPathPattern_WildcardPrefix(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		{"dev/*", "dev/database", true},
		{"dev/*", "dev/api", true},
		{"dev/*", "dev/a/b/c", true},
		{"dev/*", "dev", false},           // does not match the prefix itself
		{"dev/*", "development/x", false}, // no "/" boundary — must not match a same-prefix sibling
		{"prod/db/*", "prod/db/password", true},
		{"prod/db/*", "prod/database", false}, // the exact bypass the objective calls out
		{"prod/db/*", "prod/db", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"__"+tt.path, func(t *testing.T) {
			if got := MatchPolicyPathPattern(tt.pattern, tt.path); got != tt.want {
				t.Errorf("MatchPolicyPathPattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}
