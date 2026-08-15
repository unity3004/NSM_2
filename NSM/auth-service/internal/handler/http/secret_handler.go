package http

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/service"
)

// maxSecretRequestBodyBytes bounds POST/PUT /v1/secrets request bodies.
// Secret values are small structured credentials, not file uploads, so
// this is a generous but real resource-exhaustion guard. New to this
// resource specifically — no other handler in this codebase limits
// request body size yet (see this phase's own final report); this isn't
// a duplicate of anything, it's filling a gap the Secrets Engine's higher
// sensitivity warrants closing now rather than waiting for a
// codebase-wide retrofit.
const maxSecretRequestBodyBytes = 256 * 1024 // 256 KiB

// secretHandler translates HTTP requests into service.SecretService calls
// and service results back into dto.* JSON — nothing else. It never
// encrypts, never authorizes (that's requirePermission in router.go, and
// SecretService's own internal check — see that type's doc comment for
// why both exist), never writes to Postgres, and never appends an audit
// event itself: SecretService already does all of that internally, so
// duplicating any of it here would mean two places that could disagree
// about what happened.
type secretHandler struct {
	svc *service.SecretService
}

// list implements GET /v1/secrets — metadata only, matching the exact
// shape userHandler.list already uses for pagination (dto.PageMeta), not
// a second pagination convention: this codebase has no real cursor
// implementation to plug in yet (see repository.SecretFilter), so this
// mirrors user list's own "hardcoded Limit/HasMore until one exists"
// honesty rather than inventing one here first.
func (h *secretHandler) list(w http.ResponseWriter, r *http.Request) {
	items, err := h.svc.ListSecrets(r.Context(), service.ListSecretsInput{
		OrganizationID:        organizationIDFromRequest(r),
		Filter:                repository.SecretFilter{Limit: 20},
		ActorUserID:           actorUserID(r),
		ActorIsServiceAccount: isServiceAccount(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.SecretResponse, 0, len(items))
	for _, m := range items {
		out = append(out, dto.SecretResponseFromMetadata(m))
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.SecretResponse `json:"data"`
		Page dto.PageMeta         `json:"page"`
	}{Data: out, Page: dto.PageMeta{HasMore: false, Limit: 20}})
}

// create implements POST /v1/secrets.
func (h *secretHandler) create(w http.ResponseWriter, r *http.Request) {
	var req dto.SecretCreateRequest
	if !decodeSecretJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	meta, err := h.svc.CreateSecret(r.Context(), service.CreateSecretInput{
		OrganizationID:        organizationIDFromRequest(r),
		Path:                  req.Path,
		Payload:               req.Data,
		ActorUserID:           actorUserID(r),
		ActorIsServiceAccount: isServiceAccount(r),
		IPAddress:             clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.SecretResponseFromMetadata(meta))
}

// get implements GET /v1/secrets/{path...} — the one handler in this file
// whose response can carry a decrypted value. That's only safe because
// requirePermission("secrets:read", ...) (router.go) and
// SecretService.GetSecret's own internal RBAC check both already ran
// before this method's first line — see GetSecret's own doc comment: it
// checks authorization strictly before touching the database or
// decrypting anything, in that order, on purpose.
//
// {path...} (router.go) is a Go 1.22 ServeMux trailing wildcard: r.PathValue
// returns everything after "/v1/secrets/" verbatim, slashes included
// (e.g. "prod/database" for GET /v1/secrets/prod/database) — this is a
// logical, hierarchical secret identifier, never interpreted as a
// filesystem path anywhere in this call chain. No path-cleaning happens
// here beyond what net/http.ServeMux itself already does before routing
// (collapsing/redirecting "." and ".." segments — see TestSecretsHandler_
// PathTraversalRejected in this package's test file and the e2e path
// traversal test for what's actually verified); the authoritative
// rejection of any traversal-shaped path that reaches this far is
// util.ValidateSecretPath, called inside SecretService itself.
func (h *secretHandler) get(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	// ?versions=true is a distinct response shape (version metadata only,
	// never a value) sharing this route rather than a separate one — see
	// dto.SecretRollbackRequest's own doc comment for why a literal
	// "/versions" path segment can't follow {path...} in this router. Any
	// non-empty value is accepted (mirrors this handler's own existing
	// leniency on If-Match's surrounding quotes) since this parameter is
	// only ever a presence flag, never echoed back or compared as data.
	if r.URL.Query().Get("versions") != "" {
		h.listVersions(w, r, path)
		return
	}

	var version *int
	if raw := r.URL.Query().Get("version"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError, "version must be a positive integer.", nil)
			return
		}
		version = &v
	}

	val, err := h.svc.GetSecret(r.Context(), service.GetSecretInput{
		OrganizationID:        organizationIDFromRequest(r),
		Path:                  path,
		Version:               version,
		ActorUserID:           actorUserID(r),
		ActorIsServiceAccount: isServiceAccount(r),
		IPAddress:             clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.SecretValueResponseFromValue(val))
}

// listVersions implements GET /v1/secrets/{path...}?versions=true —
// version metadata only (dto.SecretVersionResponse has no field a
// ciphertext, nonce, or key ID could occupy), newest first, exactly as
// SecretService.ListVersions returns them.
func (h *secretHandler) listVersions(w http.ResponseWriter, r *http.Request, path string) {
	versions, err := h.svc.ListVersions(r.Context(), service.ListVersionsInput{
		OrganizationID:        organizationIDFromRequest(r),
		Path:                  path,
		ActorUserID:           actorUserID(r),
		ActorIsServiceAccount: isServiceAccount(r),
		IPAddress:             clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.SecretVersionResponse, 0, len(versions))
	for _, v := range versions {
		out = append(out, dto.SecretVersionResponseFromMetadata(v))
	}
	// No dto.PageMeta here, unlike every other list endpoint in this
	// codebase: a secret's version history is never paginated — every
	// non-destroyed version is returned every time, which is what makes
	// ListVersions' own "newest first, everything" contract meaningful in
	// the first place (a partial history would silently misrepresent a
	// secret's own current version if 000024's schema ever grew enough
	// versions to need a real cursor, which no operational secret does
	// today).
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.SecretVersionResponse `json:"data"`
	}{Data: out})
}

// rollback implements POST /v1/secrets/rollback — a collection-level
// route, not /v1/secrets/{path...}/rollback, for the identical routing
// reason GET /v1/secrets/{path...}?versions=true isn't
// GET /v1/secrets/{path...}/versions (see dto.SecretRollbackRequest's own
// doc comment). Requires secrets:rollback (router.go), a distinct
// permission from secrets:update — see permSecretsRollback's own doc
// comment in secret_service.go.
//
// The expected current version is required via the identical If-Match
// header PUT (update) already requires — see that handler's own doc
// comment on why this can never be optional; RollbackSecretInput.ExpectedVersion
// carries the same "don't silently overwrite a change you didn't know
// about" guarantee for rollback that ExpectedVersion already gives update.
func (h *secretHandler) rollback(w http.ResponseWriter, r *http.Request) {
	expected, ok := parseIfMatch(r)
	if !ok {
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError,
			`If-Match header is required and must name the current version, e.g. If-Match: "3".`, nil)
		return
	}

	var req dto.SecretRollbackRequest
	if !decodeSecretJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	meta, err := h.svc.RollbackSecret(r.Context(), service.RollbackSecretInput{
		OrganizationID:        organizationIDFromRequest(r),
		Path:                  req.Path,
		TargetVersion:         req.Version,
		ExpectedVersion:       expected,
		ActorUserID:           actorUserID(r),
		ActorIsServiceAccount: isServiceAccount(r),
		IPAddress:             clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.SecretResponseFromMetadata(meta))
}

// update implements PUT /v1/secrets/{path...}. The expected current
// version is required via the If-Match header (e.g. `If-Match: "3"`),
// never the body — mirroring SecretService.UpdateSecret's own mandatory
// (never optional) ExpectedVersion field: there is no path through this
// handler that lets a client update a secret without stating what
// version it believes it's replacing. A mismatch surfaces as
// entity.ErrVersionConflict -> 409 (see writeServiceError); a missing or
// malformed header is rejected here, at the HTTP boundary, as 422 before
// any service call, encryption, or database access happens at all.
func (h *secretHandler) update(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")

	expected, ok := parseIfMatch(r)
	if !ok {
		writeErrorEnvelope(w, r, http.StatusUnprocessableEntity, dto.CodeValidationError,
			`If-Match header is required and must name the current version, e.g. If-Match: "3".`, nil)
		return
	}

	var req dto.SecretUpdateRequest
	if !decodeSecretJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	meta, err := h.svc.UpdateSecret(r.Context(), service.UpdateSecretInput{
		OrganizationID:        organizationIDFromRequest(r),
		Path:                  path,
		ExpectedVersion:       expected,
		Payload:               req.Data,
		ActorUserID:           actorUserID(r),
		ActorIsServiceAccount: isServiceAccount(r),
		IPAddress:             clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.SecretResponseFromMetadata(meta))
}

// delete implements DELETE /v1/secrets/{path...} — soft delete only (see
// SecretService.DeleteSecret's own doc comment); permanent destruction is
// not implemented anywhere in this codebase yet.
func (h *secretHandler) delete(w http.ResponseWriter, r *http.Request) {
	path := r.PathValue("path")
	err := h.svc.DeleteSecret(r.Context(), service.DeleteSecretInput{
		OrganizationID:        organizationIDFromRequest(r),
		Path:                  path,
		ActorUserID:           actorUserID(r),
		ActorIsServiceAccount: isServiceAccount(r),
		IPAddress:             clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseIfMatch extracts the integer version an If-Match header names,
// e.g. `If-Match: "3"` -> 3, 3. Surrounding double quotes are optional —
// both `"3"` and `3` are accepted, since this codebase has no other ETag
// usage anywhere to hold this to a stricter RFC 7232 parser against, and
// leniency here costs nothing: the value is only ever used as an integer
// passed to UpdateSecretInput.ExpectedVersion, never echoed back or
// compared as a string.
func parseIfMatch(r *http.Request) (int, bool) {
	raw := strings.Trim(r.Header.Get("If-Match"), `" `)
	if raw == "" {
		return 0, false
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// decodeSecretJSON wraps decodeJSON with two checks new to this resource
// (see maxSecretRequestBodyBytes's own comment): a required
// application/json Content-Type, and a hard cap on request body size via
// http.MaxBytesReader — decodeJSON's json.Decoder would otherwise read an
// unbounded body into memory before ever reporting a parse error.
func decodeSecretJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeErrorEnvelope(w, r, http.StatusBadRequest, dto.CodeMalformedRequest, "Content-Type must be application/json.", nil)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSecretRequestBodyBytes)
	return decodeJSON(w, r, dst)
}
