package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// generateEd25519PrivateKeyPEM returns freshly generated (never persisted
// to the repository, never reused across test runs) PKCS#8 PEM content —
// the "PEM-encoded private key" format LoadSigningKeySet/
// ParseEd25519PrivateKeyPEM parse.
func generateEd25519PrivateKeyPEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestLoadSigningKeySet_FromInlinePEM(t *testing.T) {
	pemContent := generateEd25519PrivateKeyPEM(t)

	keys, err := LoadSigningKeySet("key-1", pemContent, "")
	if err != nil {
		t.Fatalf("LoadSigningKeySet() error = %v, want nil", err)
	}
	if keys.CurrentKeyID != "key-1" {
		t.Errorf("CurrentKeyID = %q, want %q", keys.CurrentKeyID, "key-1")
	}
	if len(keys.PrivateKey) == 0 {
		t.Error("PrivateKey is empty")
	}
	pub, ok := keys.PublicKeys["key-1"]
	if !ok || len(pub) == 0 {
		t.Error("PublicKeys[\"key-1\"] missing or empty")
	}
	// The derived public key must actually be this private key's own
	// public half, not an unrelated value.
	if !pub.Equal(keys.PrivateKey.Public()) {
		t.Error("derived public key does not match the loaded private key")
	}
}

func TestLoadSigningKeySet_FromFilePath(t *testing.T) {
	pemContent := generateEd25519PrivateKeyPEM(t)
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, []byte(pemContent), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keys, err := LoadSigningKeySet("key-1", "", path)
	if err != nil {
		t.Fatalf("LoadSigningKeySet() error = %v, want nil", err)
	}
	if len(keys.PrivateKey) == 0 {
		t.Error("PrivateKey is empty")
	}
}

// TestLoadSigningKeySet_PathWinsOverInlinePEM proves the documented
// precedence directly: when both are set, the file's content is what
// actually gets loaded, not the inline value.
func TestLoadSigningKeySet_PathWinsOverInlinePEM(t *testing.T) {
	filePEM := generateEd25519PrivateKeyPEM(t)
	inlinePEM := generateEd25519PrivateKeyPEM(t)
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	if err := os.WriteFile(path, []byte(filePEM), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keys, err := LoadSigningKeySet("key-1", inlinePEM, path)
	if err != nil {
		t.Fatalf("LoadSigningKeySet() error = %v, want nil", err)
	}
	wantKey, err := ParseEd25519PrivateKeyPEM(filePEM)
	if err != nil {
		t.Fatalf("ParseEd25519PrivateKeyPEM(filePEM): %v", err)
	}
	if !keys.PrivateKey.Equal(wantKey) {
		t.Error("LoadSigningKeySet used the inline PEM instead of the file at privateKeyPath")
	}
}

func TestLoadSigningKeySet_MissingKeyID(t *testing.T) {
	_, err := LoadSigningKeySet("", generateEd25519PrivateKeyPEM(t), "")
	if err == nil {
		t.Fatal("LoadSigningKeySet() with an empty key ID = nil error, want one")
	}
}

func TestLoadSigningKeySet_NoKeyMaterial(t *testing.T) {
	_, err := LoadSigningKeySet("key-1", "", "")
	if !errors.Is(err, ErrNoPrivateKey) {
		t.Errorf("LoadSigningKeySet() with no key material, error = %v, want ErrNoPrivateKey", err)
	}
}

func TestLoadSigningKeySet_InvalidPEM(t *testing.T) {
	_, err := LoadSigningKeySet("key-1", "this is not PEM at all", "")
	if !errors.Is(err, ErrInvalidKeyPEM) {
		t.Errorf("LoadSigningKeySet() with garbage PEM, error = %v, want ErrInvalidKeyPEM", err)
	}
}

// TestLoadSigningKeySet_WrongKeyType proves an RSA key — a common,
// otherwise-valid PKCS#8 PEM — is rejected rather than silently accepted
// as something it isn't.
func TestLoadSigningKeySet_WrongKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemContent := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	_, err = LoadSigningKeySet("key-1", pemContent, "")
	if !errors.Is(err, ErrWrongKeyType) {
		t.Errorf("LoadSigningKeySet() with an RSA key, error = %v, want ErrWrongKeyType", err)
	}
}

func TestParseEd25519PublicKeyPEM(t *testing.T) {
	priv, err := ParseEd25519PrivateKeyPEM(generateEd25519PrivateKeyPEM(t))
	if err != nil {
		t.Fatalf("ParseEd25519PrivateKeyPEM: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	pub, err := ParseEd25519PublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKeyPEM() error = %v, want nil", err)
	}
	if !pub.Equal(priv.Public()) {
		t.Error("parsed public key does not match the private key it was derived from")
	}
}
