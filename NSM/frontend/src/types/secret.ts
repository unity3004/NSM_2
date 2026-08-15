// Mirrors auth-service/internal/dto/secret.go exactly. Notably,
// SecretResponse has no field a decrypted value, ciphertext, nonce, or key
// could occupy — only SecretValueResponse (GET /v1/secrets/{path}'s own
// body) carries `data`, and only because that one request already passed
// server-side secrets:read authorization.

/** GET /v1/secrets list rows, and POST/PUT /v1/secrets' response body —
 * metadata only. */
export interface SecretResponse {
  path: string
  version: number
  created_at: string
  updated_at: string
}

/** GET /v1/secrets/{path}'s body — SecretResponse's fields plus the
 * decrypted key/value data for that specific version. */
export interface SecretValueResponse extends SecretResponse {
  data: Record<string, string>
}

/** POST /v1/secrets. The entire `data` object is encrypted as one unit by
 * the backend — there is no per-field selective encryption, so there is no
 * reason for this type to single out any one key either. */
export interface SecretCreateRequest {
  path: string
  data: Record<string, string>
}

/** PUT /v1/secrets/{path}'s body. The expected current version travels via
 * the If-Match header (see services/secretsApi.ts's updateSecret), never
 * in this body — mirroring the backend's own dto.SecretUpdateRequest,
 * which has no version field either. */
export interface SecretUpdateRequest {
  data: Record<string, string>
}

/** GET /v1/secrets/{path}?versions=true's row shape — metadata only,
 * mirrors dto.SecretVersionResponse exactly. No field here could ever
 * hold a decrypted value, ciphertext, nonce, or key ID. */
export interface SecretVersionResponse {
  version: number
  created_by: string
  created_at: string
  current: boolean
}

/** POST /v1/secrets/rollback's body. version names the historical version
 * to restore — the version the caller believes is current right now
 * travels via the identical If-Match header updateSecret already uses,
 * not a body field (mirrors dto.SecretRollbackRequest exactly; see that
 * type's own doc comment for why). */
export interface SecretRollbackRequest {
  path: string
  version: number
}
