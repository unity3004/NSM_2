import { httpClient } from "@/services/httpClient"
import type { ListResponse } from "@/types/common"
import type { AuditLogFilters, AuditLogResponse } from "@/types/audit"

function buildAuditLogQuery(filters: AuditLogFilters): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === "") continue
    params.set(key, String(value))
  }
  const query = params.toString()
  return query ? `?${query}` : ""
}

/** GET /v1/audit-logs. Requires audit:read. Every filter is optional and
 * server-validated (dto.AuditLogQuery.Validate) — an invalid enum value
 * or out-of-range limit comes back as a 422, surfaced through this call's
 * own ApiError like any other endpoint. */
export function listAuditLogs(
  filters: AuditLogFilters,
  signal?: AbortSignal,
): Promise<ListResponse<AuditLogResponse>> {
  return httpClient.get<ListResponse<AuditLogResponse>>(`/v1/audit-logs${buildAuditLogQuery(filters)}`, { signal })
}
