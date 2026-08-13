package dto

import (
	"regexp"
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// roleNamePattern bounds LeaseCreateRequest.Role the same deliberately
// narrow way util.ValidateSecretPath bounds a secret path — letters,
// digits, '.', '_', '-' only (Sprint 5 Task 3). A role name is never
// interpreted as a SQL identifier anywhere in this codebase (see
// leasing/postgres.Provider's own doc comment: it is a lookup key into
// an operator-configured map, nothing more), but it does get echoed back
// in audit metadata and GET /v1/leases/{id} responses, so it is still
// worth constraining to a safe, unsurprising character set at the wire
// boundary.
var roleNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// LeaseCreateRequest matches POST /v1/leases' body. TTL is a
// *time.Duration-shaped string (Go duration syntax, e.g. "1h", "30m"),
// pointer so an omitted field is distinguishable from an explicitly
// zero/negative one: omitted means "use the server's configured default
// TTL" (service.LeaseService.effectiveTTL); an explicit non-positive or
// unparseable value is rejected outright by Validate below, never
// silently treated as "omitted" or "unlimited" — the objective's own
// "never allow a client to request an arbitrary unlimited TTL" and
// "negative/zero TTL" security-test requirements, enforced at the wire
// boundary before this ever reaches the service layer.
type LeaseCreateRequest struct {
	Type string `json:"type"`
	Path string `json:"path"`
	// Role selects one entry from an operator-configured catalog — e.g.
	// "payment-readonly" — never a database, schema, or privilege list
	// directly (Sprint 5 Task 3). Optional: DevCredentialProvider and
	// any future provider with nothing to select ignore it entirely;
	// leasing/postgres.Provider requires it and rejects an unknown name
	// with service.ErrUnknownLeaseType's own sibling error.
	Role      *string `json:"role,omitempty"`
	TTL       *string `json:"ttl,omitempty"`
	Renewable bool    `json:"renewable,omitempty"`
}

// ParsedTTL parses TTL if present, returning (0, nil) for an omitted
// field — the "use the default" signal service.CreateLeaseInput.RequestedTTL
// already treats zero as. Validate must be called first; this method
// re-parses rather than caching the result purely to keep
// LeaseCreateRequest itself a plain, comparable DTO with no parse-state
// field, the same "Validate and the accessor both call the same parser,
// neither trusts the other's cached opinion" shape this codebase has no
// existing precedent to contradict.
func (r LeaseCreateRequest) ParsedTTL() (time.Duration, error) {
	if r.TTL == nil {
		return 0, nil
	}
	return time.ParseDuration(*r.TTL)
}

func (r LeaseCreateRequest) Validate() error {
	var errs ValidationErrors
	if r.Type == "" {
		errs.Add("type", "is required")
	}
	if len(r.Path) == 0 || len(r.Path) > 1040 {
		errs.Add("path", "is required and must be at most 1040 characters")
	}
	if r.Role != nil && !roleNamePattern.MatchString(*r.Role) {
		errs.Add("role", "may only contain letters, digits, '.', '_', and '-', and must be 1-100 characters")
	}
	if r.TTL != nil {
		d, err := time.ParseDuration(*r.TTL)
		if err != nil {
			errs.Add("ttl", `must be a valid duration string (e.g. "1h", "30m")`)
		} else if d <= 0 {
			errs.Add("ttl", "must be a positive duration")
		}
	}
	return errs.Err()
}

// LeaseRenewRequest matches POST /v1/leases/{id}/renew's (optional) body
// — the identical optional-TTL shape LeaseCreateRequest uses, for the
// identical reason.
type LeaseRenewRequest struct {
	TTL *string `json:"ttl,omitempty"`
}

func (r LeaseRenewRequest) ParsedTTL() (time.Duration, error) {
	if r.TTL == nil {
		return 0, nil
	}
	return time.ParseDuration(*r.TTL)
}

func (r LeaseRenewRequest) Validate() error {
	var errs ValidationErrors
	if r.TTL != nil {
		d, err := time.ParseDuration(*r.TTL)
		if err != nil {
			errs.Add("ttl", `must be a valid duration string (e.g. "1h", "30m")`)
		} else if d <= 0 {
			errs.Add("ttl", "must be a positive duration")
		}
	}
	return errs.Err()
}

// LeaseRevokeRequest matches POST /v1/leases/{id}/revoke's (optional)
// body.
type LeaseRevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// LeaseResponse is every lease-lifecycle endpoint's metadata shape —
// GET/POST/renew/revoke all return this same shape (POST additionally
// carries Credential — see LeaseCreatedResponse). Deliberately no field
// here could ever hold credential material: TTL/ExpiresAt/Status/etc.
// are the entirety of what this type can express, the same "the type
// itself is the safety boundary, not a convention callers have to
// remember" property dto.ApiKeyResponse's own doc comment already
// establishes for credential metadata.
type LeaseResponse struct {
	LeaseID      string     `json:"lease_id"`
	LeaseType    string     `json:"lease_type"`
	ResourcePath string     `json:"resource_path"`
	Status       string     `json:"status"`
	Renewable    bool       `json:"renewable"`
	TTL          string     `json:"ttl"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	// ProviderMetadata is entity.Lease.Metadata verbatim — safe,
	// non-sensitive, provider-supplied context only (e.g.
	// {"username": "vlt_...", "database": "payment_db", "role_template":
	// "payment-readonly"} for a Postgres lease). Every
	// DynamicCredentialProvider implementation is contractually
	// forbidden from ever putting a password or other credential
	// material here (see leasing.Credential.Metadata's own doc comment)
	// — this field exposing it verbatim is what makes that contract
	// enforceable at all: there is no second, separate "safe subset"
	// filter downstream of the provider that could itself have a bug.
	ProviderMetadata map[string]any `json:"provider_metadata,omitempty"`
}

func LeaseResponseFromEntity(l *entity.Lease) LeaseResponse {
	return LeaseResponse{
		LeaseID:          l.ID,
		LeaseType:        l.LeaseType,
		ResourcePath:     l.ResourcePath,
		Status:           string(l.Status),
		Renewable:        l.Renewable,
		TTL:              l.TTL.String(),
		CreatedAt:        l.CreatedAt,
		ExpiresAt:        l.ExpiresAt,
		RevokedAt:        l.RevokedAt,
		ProviderMetadata: l.Metadata,
	}
}

// LeaseCreatedResponse is POST /v1/leases' one-and-only response shape
// that carries Credential — see that field's own doc comment. Never
// returned by GET /v1/leases/{id}, POST .../renew, or POST .../revoke:
// LeaseResponse alone is what all three of those return, and none of
// them has a Credential field to populate even if a handler bug tried.
type LeaseCreatedResponse struct {
	LeaseResponse
	// Credential is the raw, sensitive dynamic-secret value(s) — shown
	// exactly once, in this one response, never retrievable again. See
	// leasing.Credential.Secret's own doc comment.
	Credential map[string]string `json:"credential"`
}
