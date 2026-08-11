// Mirrors auth-service/internal/dto/platform.go exactly.

/** GET /v1/platform/status's entire response — deliberately just one
 * field; see the Go type's own doc comment for what it must never leak. */
export interface PlatformStatusResponse {
  initialized: boolean
}

export interface BootstrapRequest {
  username: string
  email: string
  password: string
}

/** POST /v1/platform/bootstrap's 201 response. No token, no session — the
 * flow is bootstrap, then a real login, never an implicit one. */
export interface BootstrapResponse {
  id: string
  username: string
  email: string
  created_at: string
}
