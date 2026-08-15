// Package leasing implements Sprint 5 Task 2's dynamic-credential
// generation seam: the DynamicCredentialProvider abstraction and its one
// development-only implementation. It is deliberately narrow and
// self-contained — the same "no database, no logging, no net/http
// dependency" discipline internal/secrets already follows for envelope
// encryption (see that package's own doc comment) and for the identical
// reason: a package that cannot query a database or log cannot be made
// to persist or print a raw credential by a future one-line edit.
// internal/service.LeaseService (a database- and audit-aware caller) is
// where this package's output gets turned into a durable entity.Lease
// row and an audited event; this package itself never touches either.
//
// Sprint 5 Task 2 implemented no production credential backend (Postgres,
// AWS IAM, etc.) — only the provider interface and DevCredentialProvider,
// a development-only provider with no external system behind it at all.
// Sprint 5 Task 3 adds the first real one: internal/leasing/postgres, a
// sibling package (not this one) that implements DynamicCredentialProvider
// against a real *sql.DB — kept out of this package specifically so the
// "no database dependency" property above stays literally true of
// internal/leasing itself, the same reason internal/repository (the port)
// and internal/repository/postgres (the database-touching adapter) are
// two separate packages rather than one.
package leasing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// Credential is what a DynamicCredentialProvider hands back from a
// successful CreateCredential call. Secret is the one and only place raw
// credential material exists outside the provider's own momentary
// possession of it — LeaseService returns it to the HTTP caller exactly
// once (the creation response) and never persists it; see that method's
// own doc comment.
type Credential struct {
	// Secret is the raw, sensitive credential value(s) — e.g.
	// {"username": "...", "password": "..."}. Never logged, never
	// stored, never included in anything but the one response that
	// created it.
	Secret map[string]string
	// ProviderRef is an opaque, non-sensitive handle this same provider
	// can use later (RevokeCredential/RenewCredential) to act on the
	// underlying credential — e.g. a generated username, never a
	// password or key. Safe to persist in leases.provider_reference and
	// to return from a read endpoint.
	ProviderRef string
	// Metadata is safe, non-sensitive context about the credential —
	// safe to persist in leases.metadata and to return from
	// GET /v1/leases/{id}. Must never contain Secret's own values.
	Metadata map[string]any
}

// CreateCredentialInput is CreateCredential's argument.
type CreateCredentialInput struct {
	// ResourcePath is the canonical, already-authorized path the caller
	// requested a lease against (see LeaseService.Create) — a provider
	// may use it to decide what kind of credential to mint (e.g. which
	// database role to grant), but this package's own dev implementation
	// ignores it beyond recording it in Metadata.
	ResourcePath string
	// TTL is the lease's effective TTL (already clamped to
	// [MinTTL, MaxTTL] by LeaseService, never a raw caller-supplied
	// value) — a provider whose backing system has its own expiring
	// credentials (e.g. a database role with a VALID UNTIL clause) uses
	// this to set that expiry; DevCredentialProvider has nothing to set.
	TTL time.Duration
	// Role is an opaque (to LeaseService and to every other provider)
	// caller-supplied selector — e.g. "payment-readonly" — that only a
	// provider needing one interprets. LeaseService never inspects,
	// validates, or derives anything from this string itself (see that
	// type's own doc comment on why: no provider-specific logic belongs
	// in the generic service); PostgresCredentialProvider is the first
	// consumer, using it to select one entry from its own
	// operator-configured PostgresRoleTemplate catalog — never to accept
	// a database, schema, or privilege list directly from a caller.
	Role string
}

// DynamicCredentialProvider is the seam between LeaseService and wherever
// a dynamic credential's material actually gets minted. LeaseService
// never talks to a database driver, a cloud IAM API, or anything else
// directly — it only ever calls this interface, so a production
// deployment can register any of those (each its own
// DynamicCredentialProvider implementation, none built in this task)
// without LeaseService's code changing at all — the identical seam
// KeyProvider already establishes for envelope-encryption key material
// (see internal/secrets.KeyProvider's own doc comment).
type DynamicCredentialProvider interface {
	// Type is this provider's registration key — the "type" field a
	// lease-creation request names (see dto.LeaseCreateRequest) to select
	// which provider handles it. Stable for a given provider's lifetime;
	// never derived from request data.
	Type() string
	// CreateCredential mints a brand-new credential. Called at most once
	// per lease — renewal never calls this again (see RenewCredential).
	CreateCredential(ctx context.Context, in CreateCredentialInput) (Credential, error)
	// RevokeCredential invalidates the credential providerRef names,
	// immediately and permanently — called on explicit revocation and on
	// expiration-cleanup alike, so a provider's implementation must be
	// safe to call on an already-invalidated reference (idempotent, not
	// an error).
	RevokeCredential(ctx context.Context, providerRef string) error
	// RenewCredential extends the underlying credential's own lifetime to
	// newTTL from now, for a provider whose backing system tracks an
	// expiry independent of LeaseService's own bookkeeping (e.g. a
	// database role's VALID UNTIL). A provider with nothing of the kind
	// to extend (DevCredentialProvider) simply returns nil — renewal is
	// then purely LeaseService's own TTL/expires_at bookkeeping, which is
	// correct and sufficient on its own for a provider that never gave
	// the underlying credential an independent expiry to begin with.
	RenewCredential(ctx context.Context, providerRef string, newTTL time.Duration) error
}

// ErrUnknownProviderType means a lease-creation request named a "type"
// no DynamicCredentialProvider is registered under — see
// service.LeaseService's own provider registry.
var ErrUnknownProviderType = fmt.Errorf("leasing: no dynamic-credential provider is registered for this lease type")

// DevCredentialProvider is a DynamicCredentialProvider with no backing
// external system at all: it generates a synthetic, cryptographically
// random username/password pair and nothing else.
//
// DEVELOPMENT ONLY. This is not equivalent to a real dynamic-secret
// backend in any respect: nothing outside this process's own response
// ever knows this "credential" exists, granting it no actual access to
// anything — Revoke/Renew are bookkeeping no-ops because there is no real
// external credential for them to act on. It exists to let this task
// deliver and prove out the entire lease lifecycle (creation, TTL
// clamping, expiration, renewal, revocation, authorization, audit) end to
// end without requiring a real credential backend's infrastructure to
// exist yet — the identical role DevKeyProvider plays for envelope
// encryption (see that type's own doc comment). Never point this at a
// production deployment as the only registered provider for a lease type
// anyone actually depends on for real access.
type DevCredentialProvider struct{}

func NewDevCredentialProvider() *DevCredentialProvider { return &DevCredentialProvider{} }

func (p *DevCredentialProvider) Type() string { return "dev-credential" }

// CreateCredential generates a random username ("dyn_<12 hex chars>") and
// a 24-byte (32 base64url characters) random password — the same
// crypto/rand + base64url shape util.NewOpaqueToken already uses for
// session/refresh tokens, applied here to a credential this package's own
// doc comment is explicit grants no real access to anything.
func (p *DevCredentialProvider) CreateCredential(_ context.Context, in CreateCredentialInput) (Credential, error) {
	usernameSuffix := make([]byte, 6)
	if _, err := rand.Read(usernameSuffix); err != nil {
		return Credential{}, fmt.Errorf("leasing: generating dev credential username: %w", err)
	}
	username := "dyn_" + hex.EncodeToString(usernameSuffix)

	passwordBytes := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		return Credential{}, fmt.Errorf("leasing: generating dev credential password: %w", err)
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)

	return Credential{
		Secret:      map[string]string{"username": username, "password": password},
		ProviderRef: username,
		Metadata:    map[string]any{"username": username, "resource_path": in.ResourcePath},
	}, nil
}

// RevokeCredential is a no-op: DevCredentialProvider never granted any
// real access for there to be anything to revoke. Never returns an
// error, matching the interface's own idempotent-and-always-safe
// contract.
func (p *DevCredentialProvider) RevokeCredential(_ context.Context, _ string) error {
	return nil
}

// RenewCredential is a no-op for the identical reason RevokeCredential
// is — see this type's own doc comment.
func (p *DevCredentialProvider) RenewCredential(_ context.Context, _ string, _ time.Duration) error {
	return nil
}
