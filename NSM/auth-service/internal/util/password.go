// Package util holds small, dependency-light cross-cutting helpers used by
// more than one layer — password hashing, token signing, ID generation.
// Nothing in here knows about HTTP, SQL, or any entity; that's what keeps
// it safe to import from both internal/service and internal/repository
// without creating a layering violation.
package util

import "golang.org/x/crypto/bcrypt"

// PasswordAlgoBcrypt is the value stored in users.password_algo for hashes
// produced by this file — see entity.User.PasswordAlgo.
const PasswordAlgoBcrypt = "bcrypt"

// bcryptCost trades hashing latency for brute-force resistance. 12 is
// OWASP's current baseline for bcrypt; raise it as hardware gets faster.
const bcryptCost = 12

// HashPassword returns a salted bcrypt hash, safe to store in
// users.password_hash. bcrypt embeds its own random salt, so callers never
// need to manage one separately.
func HashPassword(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword reports whether plaintext matches a hash produced by
// HashPassword. It deliberately returns only a bool, not the underlying
// bcrypt error — the caller (service.AuthService.Login) must not be able
// to distinguish "wrong password" from "malformed hash" in its response,
// or it leaks information an attacker could use.
func VerifyPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}
