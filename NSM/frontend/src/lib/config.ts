// Vite exposes only VITE_-prefixed env vars to client code. Falls back to
// the Go API's own documented default dev address (see auth-service's
// configs/config.yaml, server.http_addr: ":8080") so `npm run dev` works
// with zero .env setup against a locally running backend.
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080"

// The Go API resolves the caller's tenant from this header today (see
// organizationIDFromRequest in auth-service/internal/handler/http/auth_handler.go)
// rather than from a subdomain or gateway header — a documented, temporary
// simplification, not something this frontend invented. Hardcoded to the
// same fixture organization test/fixtures/organizations.sql seeds, since
// there is no tenant-selection UI yet.
export const ORGANIZATION_ID = import.meta.env.VITE_ORGANIZATION_ID ?? "00000000-0000-4000-8000-000000000001"
