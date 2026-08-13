package entity

import "testing"

func TestSanitizeAuditMetadata_Nil(t *testing.T) {
	if got := SanitizeAuditMetadata(nil); got != nil {
		t.Errorf("SanitizeAuditMetadata(nil) = %v, want nil", got)
	}
}

func TestSanitizeAuditMetadata_SafeKeysPassThroughUnchanged(t *testing.T) {
	in := map[string]any{
		"path":       "prod/database",
		"version":    3,
		"username":   "alice",
		"email":      "alice@example.com",
		"role_id":    "role-1",
		"rule_count": 2,
		"operation":  "login",
		"reason":     "reuse_detected",
	}
	got := SanitizeAuditMetadata(in)
	for k, v := range in {
		if got[k] != v {
			t.Errorf("SanitizeAuditMetadata()[%q] = %v, want unchanged %v", k, got[k], v)
		}
	}
}

func TestSanitizeAuditMetadata_RedactsSensitiveKeys(t *testing.T) {
	tests := []string{
		"password", "Password", "PASSWORD",
		"password_hash", "passwd", "pwd",
		"secret", "secret_value", "client_secret",
		"token", "access_token", "refresh_token", "api_token",
		"credential", "credentials",
		"key", "api_key", "private_key", "encryption_key", "wrapped_dek",
		"ciphertext", "plaintext",
		"nonce", "auth_tag", "authTag",
		"hash", "record_hash", "prev_hash",
		"signature",
		"private_data",
	}
	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			in := map[string]any{key: "sensitive-value-that-must-not-survive"}
			got := SanitizeAuditMetadata(in)
			if got[key] != redactedValue {
				t.Errorf("SanitizeAuditMetadata()[%q] = %v, want %q", key, got[key], redactedValue)
			}
		})
	}
}

func TestSanitizeAuditMetadata_RedactsRegardlessOfValueType(t *testing.T) {
	in := map[string]any{
		"password": 12345, // not even a string — must still be redacted by key name alone
	}
	got := SanitizeAuditMetadata(in)
	if got["password"] != redactedValue {
		t.Errorf("got[password] = %v, want %q", got["password"], redactedValue)
	}
}

func TestSanitizeAuditMetadata_RecursesOneLevelIntoNestedMaps(t *testing.T) {
	in := map[string]any{
		"safe": "ok",
		"nested": map[string]any{
			"password": "should-be-redacted",
			"path":     "prod/database",
		},
	}
	got := SanitizeAuditMetadata(in)
	nested, ok := got["nested"].(map[string]any)
	if !ok {
		t.Fatalf("got[nested] = %v (%T), want map[string]any", got["nested"], got["nested"])
	}
	if nested["password"] != redactedValue {
		t.Errorf("nested[password] = %v, want %q", nested["password"], redactedValue)
	}
	if nested["path"] != "prod/database" {
		t.Errorf("nested[path] = %v, want unchanged", nested["path"])
	}
}

func TestSanitizeAuditMetadata_DoesNotMutateInput(t *testing.T) {
	in := map[string]any{"password": "secret-value"}
	_ = SanitizeAuditMetadata(in)
	if in["password"] != "secret-value" {
		t.Error("SanitizeAuditMetadata mutated its input map in place")
	}
}

func TestSanitizeAuditMetadata_EmptyMap(t *testing.T) {
	got := SanitizeAuditMetadata(map[string]any{})
	if len(got) != 0 {
		t.Errorf("SanitizeAuditMetadata({}) = %v, want empty", got)
	}
}
