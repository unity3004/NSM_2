// Command devkeygen generates a disposable Ed25519 private key for local
// development only, in the exact PKCS#8 PEM shape security.LoadSigningKeySet
// already expects from AUTH_ACCESS_TOKEN_PRIVATE_KEY_PATH (see
// internal/security/keys.go). It exists solely so `docker compose up` has
// real key material to mount into the app container without that material
// ever being committed: docker/docker-compose.yml points
// AUTH_ACCESS_TOKEN_PRIVATE_KEY_PATH at the file this writes, and
// docker/.dev-secrets/ (this command's default output directory) is
// git-ignored.
//
// This key is development/test-only. Never point it at a real deployment,
// and never commit its output.
//
// Usage: go run ./cmd/devkeygen [output-path]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

const defaultOutputPath = "docker/.dev-secrets/access-token-signing-key.pem"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "devkeygen:", err)
		os.Exit(1)
	}
}

func run() error {
	outputPath := defaultOutputPath
	if len(os.Args) > 1 {
		outputPath = os.Args[1]
	}

	if _, err := os.Stat(outputPath); err == nil {
		fmt.Printf("devkeygen: %s already exists, leaving it in place\n", outputPath)
		return nil
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	// 0600: this is a private key, even if only a development one.
	if err := os.WriteFile(outputPath, pemBytes, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}

	fmt.Printf("devkeygen: wrote a new development-only Ed25519 key to %s\n", outputPath)
	fmt.Println("devkeygen: this key is for local development/testing only — never commit it, never use it in production")
	return nil
}
