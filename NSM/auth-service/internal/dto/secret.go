package dto

import (
	"time"

	"github.com/acme/auth-service/internal/service"
	"github.com/acme/auth-service/internal/util"
)

// SecretCreateRequest matches components.schemas.SecretCreate. Data is the
// entire structured secret value — the whole map is encrypted as one unit
// by SecretService, never a per-field selective encryption — so there is
// no separate "password" field here to single out.
type SecretCreateRequest struct {
	Path string            `json:"path"`
	Data map[string]string `json:"data"`
}

// Validate reuses util.ValidateSecretPath directly — the same rules
// repository.SecretRepository's schema and SecretService's own internal
// re-validation already enforce (see that function's doc comment) — so a
// malformed path is reported here, at the DTO boundary, as a clear 422
// with a field-level message, before ever reaching the service. This does
// not replace SecretService's own path validation; it exists purely so a
// client gets a better error than the service's generic path-rejection
// would produce standing alone.
func (r SecretCreateRequest) Validate() error {
	var errs ValidationErrors
	path := util.NormalizeSecretPath(r.Path)
	if err := util.ValidateSecretPath(path); err != nil {
		errs.Add("path", err.Error())
	}
	if len(r.Data) == 0 {
		errs.Add("data", "must not be empty")
	}
	return errs.Err()
}

// SecretUpdateRequest matches components.schemas.SecretUpdate. The
// expected current version travels via the If-Match header (see
// secret_handler.go's update method), never the body — the same
// "identity/attribution never comes from the request body" discipline
// this codebase already applies to actor identity, applied here to
// optimistic-concurrency state instead.
type SecretUpdateRequest struct {
	Data map[string]string `json:"data"`
}

func (r SecretUpdateRequest) Validate() error {
	var errs ValidationErrors
	if len(r.Data) == 0 {
		errs.Add("data", "must not be empty")
	}
	return errs.Err()
}

// SecretResponse is metadata only — matches components.schemas.Secret.
// There is no field on this type a ciphertext, nonce, key ID, or secret
// value could occupy; that is what makes it safe as the response body for
// create/update/list.
type SecretResponse struct {
	Path      string    `json:"path"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SecretResponseFromMetadata is the one place a service.SecretMetadata
// becomes API JSON. It takes a service-layer type, not an entity.* type —
// unlike UserResponseFromEntity — because SecretMetadata is itself already
// the service layer's own flattened, safe-to-return shape; there is no
// richer entity.Secret this response could be built from instead that
// wouldn't just be this same set of fields again.
func SecretResponseFromMetadata(m service.SecretMetadata) SecretResponse {
	return SecretResponse{Path: m.Path, Version: m.CurrentVersion, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}

// SecretValueResponse is GET /v1/secrets/{path}'s body — matches
// components.schemas.SecretValue, and is the one response type in this
// file that carries a decrypted value. That is safe here, and only here,
// because a caller only ever reaches secretHandler.get after both
// requirePermission("secrets:read", ...) (router.go) and
// SecretService.GetSecret's own internal RBAC check have already passed.
type SecretValueResponse struct {
	Path      string            `json:"path"`
	Version   int               `json:"version"`
	Data      map[string]string `json:"data"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

func SecretValueResponseFromValue(v service.SecretValue) SecretValueResponse {
	return SecretValueResponse{
		Path: v.Metadata.Path, Version: v.Version, Data: v.Payload,
		CreatedAt: v.Metadata.CreatedAt, UpdatedAt: v.Metadata.UpdatedAt,
	}
}
