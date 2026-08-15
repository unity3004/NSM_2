/**
 * Decodes a JWT's payload WITHOUT verifying its signature.
 *
 * Display-only. Never use this for an authorization decision — the backend
 * has already verified the token's signature on every request that
 * matters; this exists purely so the UI can show "who am I" (via `sub`)
 * without a dedicated /me endpoint, which this API doesn't have.
 */
export interface DecodedAccessTokenClaims {
  sub?: string
  exp?: number
  iat?: number
}

export function decodeJwtPayload(token: string): DecodedAccessTokenClaims | null {
  const parts = token.split(".")
  if (parts.length !== 3) return null

  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/")
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4)
    return JSON.parse(atob(padded)) as DecodedAccessTokenClaims
  } catch {
    return null
  }
}
