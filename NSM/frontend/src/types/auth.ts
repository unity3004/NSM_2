// Mirrors auth-service/internal/dto/auth.go exactly. Field names/optionality
// are copied from the Go struct tags, not guessed — see LoginRequest,
// RefreshRequest, and TokenResponse in that file.

export interface LoginRequest {
  email: string
  password: string
  device_fingerprint?: string
}

export interface RefreshRequest {
  refresh_token: string
}

/** Response shape for POST /v1/auth/login and POST /v1/auth/token/refresh. */
export interface TokenResponse {
  access_token: string
  refresh_token: string
  token_type: "Bearer"
  expires_in: number
  session_id: string
}
