package util

import "strings"

// NormalizeEmail applies this service's one email normalization policy —
// trim surrounding whitespace, lowercase the whole address — before an
// email is ever written to storage. This is deliberately not provider-aware
// (no Gmail dot- or plus-addressing folding): that class of normalization
// surprises users ("why did my dot disappear") and is specific to one
// provider's semantics, not a general email-address rule.
//
// Why normalize at write time at all, given the users.email column is
// CITEXT (already case-insensitive for lookups and the uq_users_org_email
// constraint): CITEXT makes *comparison* case-insensitive, but doesn't
// change what's *stored* — without this, two registrations for
// "a@b.com" and "A@B.com" would correctly collide (good), but whichever
// happened to register first would freeze an arbitrarily-cased value as
// the canonical display/audit copy forever. Normalizing before it reaches
// the repository means the stored value is always the same canonical
// form, independent of how any particular caller happened to type it.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
