package security

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	ErrNoPrivateKey  = errors.New("security: no private key material configured")
	ErrInvalidKeyPEM = errors.New("security: value is not a valid PEM-encoded key")
	ErrWrongKeyType  = errors.New("security: PEM-encoded key is not an Ed25519 key")
)

// SigningKeySet is the smallest abstraction TokenService needs to sign and
// verify access tokens, and the seam key rotation happens through: adding
// a new entry to PublicKeys (a new kid a verifier should start accepting)
// and switching CurrentKeyID/PrivateKey to point signing at it are two
// independent steps — exactly what lets a deployment roll out a new key's
// *verification* everywhere before anything is ever signed with it, and
// keep verifying tokens signed under a retired key until they naturally
// expire, all without TokenService's own code changing at all.
type SigningKeySet struct {
	CurrentKeyID string
	PrivateKey   ed25519.PrivateKey
	PublicKeys   map[string]ed25519.PublicKey
}

// LoadSigningKeySet builds a SigningKeySet from a single PEM-encoded
// PKCS#8 Ed25519 private key — the current signing key. Its public half is
// derived directly from the private key (Ed25519 key material always
// contains both), so this is the only loading function a service that
// both signs and verifies its own tokens needs; ParseEd25519PublicKeyPEM
// below exists for the opposite case a verification-only deployment would
// need instead (see Milestone 5A's report on requirement #4), and isn't
// called from anywhere in this milestone.
//
// privateKeyPath, if non-empty, wins over privateKeyPEM — a mounted secret
// file is the more realistic production mechanism than raw key bytes
// sitting in process environment. keyID must be non-empty: it's what a
// verifier's kid lookup keys on, and there is deliberately no default for
// it (see AccessTokenConfig's doc comment).
func LoadSigningKeySet(keyID, privateKeyPEM, privateKeyPath string) (*SigningKeySet, error) {
	if keyID == "" {
		return nil, fmt.Errorf("security: LoadSigningKeySet: key ID is required")
	}

	pemContent := privateKeyPEM
	if privateKeyPath != "" {
		data, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("security: reading private key file: %w", err)
		}
		pemContent = string(data)
	}
	if pemContent == "" {
		return nil, ErrNoPrivateKey
	}

	priv, err := ParseEd25519PrivateKeyPEM(pemContent)
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrWrongKeyType
	}

	return &SigningKeySet{
		CurrentKeyID: keyID,
		PrivateKey:   priv,
		PublicKeys:   map[string]ed25519.PublicKey{keyID: pub},
	}, nil
}

// ParseEd25519PrivateKeyPEM decodes a PEM block containing a PKCS#8-encoded
// Ed25519 private key — the format `openssl genpkey -algorithm ed25519`
// produces. Never logged and never echoed into an error message: a parse
// failure reports only that parsing failed, never the input that failed
// to parse.
func ParseEd25519PrivateKeyPEM(pemContent string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemContent))
	if block == nil {
		return nil, ErrInvalidKeyPEM
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyPEM, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrWrongKeyType
	}
	return priv, nil
}

// ParseEd25519PublicKeyPEM decodes a PEM block containing a PKIX-encoded
// Ed25519 public key — the counterpart a verification-only service (one
// that never holds the private key at all, per requirement #4) would use
// in place of LoadSigningKeySet.
func ParseEd25519PublicKeyPEM(pemContent string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemContent))
	if block == nil {
		return nil, ErrInvalidKeyPEM
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyPEM, err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, ErrWrongKeyType
	}
	return pub, nil
}
