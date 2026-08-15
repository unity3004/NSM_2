package config

import (
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"
)

// TestMarshalLogObject_NeverLeaksPrivateKey proves the private-key
// redaction directly, the same way jwt.signing_key/database.password are
// already proven safe by convention in this package: a config carrying a
// realistic-looking PEM value must never have that value appear anywhere
// in its logged form.
func TestMarshalLogObject_NeverLeaksPrivateKey(t *testing.T) {
	const fakePrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTOTALLYFAKEKEYMATERIALTHATMUSTNEVERAPPEAR\n-----END PRIVATE KEY-----\n"
	const fakeDevMasterKey = "VE9UQUxMWUZBS0VBRVMyNTZLRVlUSEFUTVVTVE5FVkVSQVBQRUFS" // base64, but the point is it must never appear either way

	cfg := Config{
		Environment: "development",
		AccessToken: AccessTokenConfig{
			Issuer:        "auth-service",
			KeyID:         "key-1",
			PrivateKeyPEM: fakePrivateKeyPEM,
		},
		Secrets: SecretsConfig{
			DevMasterKey: fakeDevMasterKey,
		},
	}

	enc := zapcore.NewMapObjectEncoder()
	if err := cfg.MarshalLogObject(enc); err != nil {
		t.Fatalf("MarshalLogObject() error = %v", err)
	}

	for field, value := range enc.Fields {
		s, ok := value.(string)
		if !ok {
			continue
		}
		if strings.Contains(s, fakePrivateKeyPEM) || strings.Contains(s, "TOTALLYFAKEKEYMATERIAL") {
			t.Errorf("field %q = %q leaks the private key PEM content", field, s)
		}
		if strings.Contains(s, fakeDevMasterKey) {
			t.Errorf("field %q = %q leaks the secrets dev master key", field, s)
		}
	}

	got, ok := enc.Fields["access_token.private_key_pem"].(string)
	if !ok {
		t.Fatal("access_token.private_key_pem field missing or not a string")
	}
	if got == fakePrivateKeyPEM {
		t.Error("access_token.private_key_pem was logged verbatim, not redacted")
	}
	if !strings.HasPrefix(got, "(redacted") {
		t.Errorf("access_token.private_key_pem = %q, want the standard redact() placeholder", got)
	}

	gotDevKey, ok := enc.Fields["secrets.dev_master_key"].(string)
	if !ok {
		t.Fatal("secrets.dev_master_key field missing or not a string")
	}
	if gotDevKey == fakeDevMasterKey {
		t.Error("secrets.dev_master_key was logged verbatim, not redacted")
	}
	if !strings.HasPrefix(gotDevKey, "(redacted") {
		t.Errorf("secrets.dev_master_key = %q, want the standard redact() placeholder", gotDevKey)
	}

	// A path is not itself secret, and key_id/issuer are operational
	// values — these must still be visible for the log line to be useful.
	if enc.Fields["access_token.key_id"] != "key-1" {
		t.Errorf("access_token.key_id = %v, want it logged in full", enc.Fields["access_token.key_id"])
	}
}
