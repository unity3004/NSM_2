import { httpClient } from "@/services/httpClient"
import type { LoginRequest, TokenResponse } from "@/types/auth"

/**
 * POST /v1/auth/login. Unauthenticated by design (auth: false) — there is
 * no token to attach yet, and a failed login (401 INVALID_CREDENTIALS)
 * must never trigger the refresh interceptor.
 */
export function login(credentials: LoginRequest): Promise<TokenResponse> {
  return httpClient.post<TokenResponse>("/v1/auth/login", credentials, { auth: false })
}

/**
 * POST /v1/auth/logout. Authenticated — the backend reads the session to
 * revoke from the caller's own access-token claims, never from the request
 * body. refreshToken, if provided, is also revoked (its whole token
 * family), matching the endpoint's documented "body is optional" contract.
 */
export function logout(refreshToken?: string): Promise<void> {
  return httpClient.post<void>(
    "/v1/auth/logout",
    refreshToken ? { refresh_token: refreshToken } : undefined,
  )
}
