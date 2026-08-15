import { httpClient } from "@/services/httpClient"
import type { ListResponse } from "@/types/common"
import type {
  ApiKeyCreatedResponse,
  ApiKeyCreateRequest,
  ApiKeyResponse,
  RoleGrant,
  ServiceAccountCreateRequest,
  ServiceAccountDetailResponse,
  ServiceAccountResponse,
  ServiceAccountUpdateRequest,
} from "@/types/serviceAccount"

/** GET /v1/service-accounts. Requires service_accounts:read. */
export function listServiceAccounts(signal?: AbortSignal): Promise<ListResponse<ServiceAccountResponse>> {
  return httpClient.get<ListResponse<ServiceAccountResponse>>("/v1/service-accounts", { signal })
}

/** GET /v1/service-accounts/{id} — metadata plus role/permission grants.
 * Requires service_accounts:read. */
export function getServiceAccount(id: string, signal?: AbortSignal): Promise<ServiceAccountDetailResponse> {
  return httpClient.get<ServiceAccountDetailResponse>(`/v1/service-accounts/${encodeURIComponent(id)}`, { signal })
}

/** POST /v1/service-accounts. Requires service_accounts:create. */
export function createServiceAccount(payload: ServiceAccountCreateRequest): Promise<ServiceAccountResponse> {
  return httpClient.post<ServiceAccountResponse>("/v1/service-accounts", payload, { retryOn401: false })
}

/** PATCH /v1/service-accounts/{id}. Requires service_accounts:update
 * (name/description) — a status change additionally requires
 * service_accounts:disable on the backend, the same permission split
 * users:update/users:disable already establish for human accounts. */
export function updateServiceAccount(
  id: string,
  payload: ServiceAccountUpdateRequest,
): Promise<ServiceAccountResponse> {
  return httpClient.patch<ServiceAccountResponse>(`/v1/service-accounts/${encodeURIComponent(id)}`, payload, {
    retryOn401: false,
  })
}

/** DELETE /v1/service-accounts/{id} — a hard delete; cascades to its role
 * grants and revokes every API key it owns. Requires
 * service_accounts:delete. */
export function deleteServiceAccount(id: string): Promise<void> {
  return httpClient.delete<void>(`/v1/service-accounts/${encodeURIComponent(id)}`)
}

/** POST /v1/service-accounts/{id}/roles. Requires roles:update — the same
 * permission POST /v1/users/{id}/roles already requires, applied to a
 * different principal type. */
export function assignServiceAccountRole(id: string, roleId: string): Promise<RoleGrant> {
  return httpClient.post<RoleGrant>(
    `/v1/service-accounts/${encodeURIComponent(id)}/roles`,
    { role_id: roleId },
    { retryOn401: false },
  )
}

/** DELETE /v1/service-accounts/{id}/roles/{roleId}. Requires
 * roles:update. */
export function removeServiceAccountRole(id: string, roleId: string): Promise<void> {
  return httpClient.delete<void>(
    `/v1/service-accounts/${encodeURIComponent(id)}/roles/${encodeURIComponent(roleId)}`,
  )
}

/** GET /v1/api-keys?owner_service_account_id={id}. Requires
 * api_keys:read. */
export function listServiceAccountCredentials(
  serviceAccountId: string,
  signal?: AbortSignal,
): Promise<ListResponse<ApiKeyResponse>> {
  return httpClient.get<ListResponse<ApiKeyResponse>>(
    `/v1/api-keys?owner_service_account_id=${encodeURIComponent(serviceAccountId)}`,
    { signal },
  )
}

/** POST /v1/api-keys. The response's `secret` field is the only time the
 * raw credential is ever returned — see ApiKeyCreatedResponse's own doc
 * comment. Requires api_keys:create. */
export function createCredential(payload: ApiKeyCreateRequest): Promise<ApiKeyCreatedResponse> {
  return httpClient.post<ApiKeyCreatedResponse>("/v1/api-keys", payload, { retryOn401: false })
}

/** DELETE /v1/api-keys/{id} — revocation, never a hard delete of the row.
 * Requires api_keys:delete. */
export function revokeCredential(id: string): Promise<void> {
  return httpClient.delete<void>(`/v1/api-keys/${encodeURIComponent(id)}`)
}

/** POST /v1/api-keys/{id}/rotate — issues a replacement credential and
 * revokes this one in the same call; the new secret is shown exactly
 * once, the same as creation. Requires api_keys:rotate. */
export function rotateCredential(id: string): Promise<ApiKeyCreatedResponse> {
  return httpClient.post<ApiKeyCreatedResponse>(`/v1/api-keys/${encodeURIComponent(id)}/rotate`, undefined, {
    retryOn401: false,
  })
}
