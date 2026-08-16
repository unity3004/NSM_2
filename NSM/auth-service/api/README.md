# API contract

The canonical OpenAPI 3.1 spec for this service lives one level up in the
NSM workspace, at `../../auth-service-openapi.yaml` (and its companion
narrative doc, `../../auth-service-api-design.md`), because it was
authored before this repository existed and this scaffold is meant to
implement it, not fork it.

In a standalone repository, copy that file to `api/openapi.yaml` and treat
*this* copy as canonical instead — then wire a CI check (`swagger-cli
validate` or similar) that fails the build if a handler's response shape
in `internal/dto` drifts from what `api/openapi.yaml` promises callers.
That check isn't included in `.github/workflows/ci.yml` yet; it's the
natural next addition once the spec and the code live in the same repo.
