import { httpClient } from "@/services/httpClient"
import type { ListResponse } from "@/types/common"
import type { UserCreateRequest, UserDetailResponse, UserResponse } from "@/types/user"

/** GET /v1/users/{userId} — the detail view: real role grants and
 * effective permissions, not just the bare profile fields list() returns. */
export function getUser(userId: string, signal?: AbortSignal): Promise<UserDetailResponse> {
  return httpClient.get<UserDetailResponse>(`/v1/users/${encodeURIComponent(userId)}`, { signal })
}

/** GET /v1/users — organization-scoped via the X-Organization-Id header
 * httpClient already attaches to every request. Requires users:read;
 * the backend, not this call, is what actually enforces that. */
export function listUsers(signal?: AbortSignal): Promise<ListResponse<UserResponse>> {
  return httpClient.get<ListResponse<UserResponse>>("/v1/users", { signal })
}

/** POST /v1/users — admin-created account. Requires users:create. */
export function createUser(payload: UserCreateRequest): Promise<UserResponse> {
  return httpClient.post<UserResponse>("/v1/users", payload)
}

/** POST /v1/users/{userId}/disable. Requires users:disable. */
export function disableUser(userId: string): Promise<UserResponse> {
  return httpClient.post<UserResponse>(`/v1/users/${encodeURIComponent(userId)}/disable`)
}

/** POST /v1/users/{userId}/enable. Requires users:disable (the same
 * permission gates both directions — see the backend migration's own
 * doc comment on why this isn't split into two permissions). */
export function enableUser(userId: string): Promise<UserResponse> {
  return httpClient.post<UserResponse>(`/v1/users/${encodeURIComponent(userId)}/enable`)
}

/** POST /v1/users/{userId}/roles. Requires roles:update. roleId must
 * name a role this platform already defines — there is no way to invent
 * one through this call. */
export function assignRole(userId: string, roleId: string): Promise<void> {
  return httpClient.post<void>(`/v1/users/${encodeURIComponent(userId)}/roles`, { role_id: roleId })
}

/** DELETE /v1/users/{userId}/roles/{roleId}. Requires roles:update. */
export function removeRole(userId: string, roleId: string): Promise<void> {
  return httpClient.delete<void>(`/v1/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(roleId)}`)
}
