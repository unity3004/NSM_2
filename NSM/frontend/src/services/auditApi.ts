import { httpClient } from "@/services/httpClient"
import type { AuditLogFilters, AuditLogListResponse, AuditLogResponse } from "@/types/audit"

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
): Promise<AuditLogListResponse> {
  return httpClient.get<AuditLogListResponse>(`/v1/audit-logs${buildAuditLogQuery(filters)}`, { signal })
}

/** GET /v1/audit-logs/{id}. Requires audit:read. The backend route has
 * existed since Sprint 4 Task 3 (see router.go); this is simply the first
 * client call to it — used to deep-link straight to one specific event
 * (e.g. from the dashboard's Recent Security Activity) without needing
 * that event to already be present in whatever page/filters the Audit
 * Explorer happens to be showing. */
export function getAuditLog(id: string, signal?: AbortSignal): Promise<AuditLogResponse> {
  return httpClient.get<AuditLogResponse>(`/v1/audit-logs/${encodeURIComponent(id)}`, { signal })
}
