import { httpClient } from "@/services/httpClient"
import type { ListResponse } from "@/types/common"
import type { SecretCreateRequest, SecretResponse, SecretUpdateRequest, SecretValueResponse } from "@/types/secret"

/** Encodes each path segment individually — encodeURIComponent on the
 * whole path would escape the '/' hierarchy separators the backend's
 * {path...} trailing-wildcard route (router.go) expects literally, turning
 * "prod/database" into an unmatched, malformed route instead of the
 * logical secret it names. */
function encodeSecretPath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/")
}

/** GET /v1/secrets — metadata only, never a value/ciphertext/key. Requires
 * secrets:list. */
export function listSecrets(signal?: AbortSignal): Promise<ListResponse<SecretResponse>> {
  return httpClient.get<ListResponse<SecretResponse>>("/v1/secrets", { signal })
}

/** POST /v1/secrets. Requires secrets:create. retryOn401: false — see
 * httpClient's own doc comment on RequestOptions.retryOn401: a transparent
 * retry of a create after a token refresh could surface a confusing
 * duplicate-path 409 instead of the transient auth failure that actually
 * happened. */
export function createSecret(payload: SecretCreateRequest): Promise<SecretResponse> {
  return httpClient.post<SecretResponse>("/v1/secrets", payload, { retryOn401: false })
}

/** GET /v1/secrets/{path} — the only call in this file whose response
 * carries a decrypted value. Requires secrets:read. version, if given,
 * requests that specific historical version (immutable, never the current
 * one silently substituted) instead of the current version. */
export function getSecret(path: string, version?: number, signal?: AbortSignal): Promise<SecretValueResponse> {
  const query = version !== undefined ? `?version=${version}` : ""
  return httpClient.get<SecretValueResponse>(`/v1/secrets/${encodeSecretPath(path)}${query}`, { signal })
}

/** PUT /v1/secrets/{path} — always creates a new version, never overwrites
 * an existing one. Requires secrets:update. expectedVersion is mandatory
 * (mirrors UpdateSecretInput.ExpectedVersion's own non-optional design on
 * the backend) and travels as the If-Match header, never the body; a
 * mismatch is reported as 409 VERSION_CONFLICT (see ApiError.isVersionConflict).
 * retryOn401: false for the same reason createSecret sets it. */
export function updateSecret(
  path: string,
  data: Record<string, string>,
  expectedVersion: number,
): Promise<SecretResponse> {
  return httpClient.put<SecretResponse>(
    `/v1/secrets/${encodeSecretPath(path)}`,
    { data } satisfies SecretUpdateRequest,
    { headers: { "If-Match": `"${expectedVersion}"` }, retryOn401: false },
  )
}

/** DELETE /v1/secrets/{path} — soft delete only; the backend never
 * destroys ciphertext through this call. Requires secrets:delete. */
export function deleteSecret(path: string): Promise<void> {
  return httpClient.delete<void>(`/v1/secrets/${encodeSecretPath(path)}`)
}
