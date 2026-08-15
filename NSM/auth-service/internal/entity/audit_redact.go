package entity

import "strings"

// sensitiveMetadataKeySubstrings is the central denylist
// SanitizeAuditMetadata checks every metadata key against, case-
// insensitively and by substring (not exact match) — deliberately broad:
// a false positive redacts a key that was actually safe (visible,
// harmless, just overly cautious); a false negative leaks a secret into
// an immutable, hash-chained, long-retained audit trail. Those two
// failure modes are not symmetric, so this list is written to prefer the
// former. Every current audit call site already hand-picks safe metadata
// keys (path, version, rule_count, username, ...) and none of them
// collide with any entry here — this exists purely as defense-in-depth
// against a future call site that accidentally passes something it
// shouldn't, not because any call site does today (see this task's own
// final report for the repository-wide grep that confirmed that).
var sensitiveMetadataKeySubstrings = []string{
	"password", "passwd", "pwd",
	"secret",
	"token",
	"credential",
	"key", // covers "api_key", "private_key", "encryption_key", "key_material", bare "key", etc.
	"ciphertext",
	"plaintext",
	"nonce",
	"auth_tag",
	"authtag",
	"wrapped_dek",
	"hash",
	"signature",
	"private",
}

// redactedValue replaces a value SanitizeAuditMetadata rejected — visible
// in the stored record (an auditor reading the row can see metadata was
// withheld and why the key looked dangerous), never silently dropped: a
// missing key and a redacted key must not look the same to someone
// reconstructing an incident later.
const redactedValue = "[REDACTED]"

// SanitizeAuditMetadata is the one place a metadata map is checked before
// it's allowed into an audit_logs row — applied centrally at
// postgres.auditLogRepository.Append (Sprint 4 Task 3), so every writer
// gets this protection whether or not it remembers to. Keys are matched
// case-insensitively by substring against sensitiveMetadataKeySubstrings;
// a matching key's value is replaced with "[REDACTED]" regardless of its
// type. Nested map[string]any values are sanitized one level recursively
// (the only nesting shape any current call site's metadata ever
// produces) — anything deeper, or a slice containing maps, is left as-is,
// since no call site in this codebase constructs that shape and adding
// unbounded recursion for a case that cannot currently occur would be
// speculative complexity this task's own instructions caution against.
//
// This is defense-in-depth, not the primary control: every existing call
// site already hand-picks which fields go into Metadata (see e.g.
// SecretService.recordSecretAudit's own doc comment — "metadata never
// carries plaintext, ciphertext, a nonce, or key material... every call
// site above passes only path and version"). This function exists so
// that discipline is enforced even if a future call site forgets it.
func SanitizeAuditMetadata(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if isSensitiveMetadataKey(k) {
			out[k] = redactedValue
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			out[k] = SanitizeAuditMetadata(nested)
			continue
		}
		out[k] = v
	}
	return out
}

func isSensitiveMetadataKey(key string) bool {
	lower := strings.ToLower(key)
	for _, substr := range sensitiveMetadataKeySubstrings {
		if strings.Contains(lower, substr) {
			return true
		}
	}
	return false
}
