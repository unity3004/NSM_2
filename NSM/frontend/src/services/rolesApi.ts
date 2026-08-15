import { httpClient } from "@/services/httpClient"
import type { PermissionResponse, RoleWithPermissionsResponse } from "@/types/rbac"

/** GET /v1/roles. Requires roles:read. Returns every role visible to the
 * caller's organization (tenant-defined plus system-wide), each already
 * carrying its permissions and live user count — no follow-up requests
 * needed to render the Roles page. */
export function listRoles(signal?: AbortSignal): Promise<{ data: RoleWithPermissionsResponse[] }> {
  return httpClient.get<{ data: RoleWithPermissionsResponse[] }>("/v1/roles", { signal })
}

/** GET /v1/roles/{roleId}. Requires roles:read. */
export function getRole(roleId: string, signal?: AbortSignal): Promise<RoleWithPermissionsResponse> {
  return httpClient.get<RoleWithPermissionsResponse>(`/v1/roles/${encodeURIComponent(roleId)}`, { signal })
}

/** GET /v1/permissions. Requires roles:read. The full, flat,
 * platform-seeded catalog — never tenant-scoped. */
export function listPermissions(signal?: AbortSignal): Promise<{ data: PermissionResponse[] }> {
  return httpClient.get<{ data: PermissionResponse[] }>("/v1/permissions", { signal })
}
