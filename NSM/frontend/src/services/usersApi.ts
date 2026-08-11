import { httpClient } from "@/services/httpClient"
import type { ListResponse } from "@/types/common"
import type { UserResponse } from "@/types/user"

/** GET /v1/users/{userId}. */
export function getUser(userId: string, signal?: AbortSignal): Promise<UserResponse> {
  return httpClient.get<UserResponse>(`/v1/users/${encodeURIComponent(userId)}`, { signal })
}

/** GET /v1/users — organization-scoped via the X-Organization-Id header
 * httpClient already attaches to every request. */
export function listUsers(signal?: AbortSignal): Promise<ListResponse<UserResponse>> {
  return httpClient.get<ListResponse<UserResponse>>("/v1/users", { signal })
}
