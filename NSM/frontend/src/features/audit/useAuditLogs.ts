import { useQuery } from "@tanstack/react-query"
import { getAuditLog, listAuditLogs } from "@/services/auditApi"
import type { AuditLogFilters } from "@/types/audit"

/** One page of audit_logs, refetched whenever filters (including cursor)
 * change — the caller (AuditLogsPage) owns accumulating pages across a
 * "Load more" click and resetting on filter change, the same
 * "the hook fetches one page, the page component owns pagination state"
 * split this codebase has no prior paginated-list precedent to follow
 * more closely (every existing list page hardcodes has_more: false — see
 * secretsApi.ts's own comment on why). */
export function useAuditLogs(filters: AuditLogFilters, options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["audit-logs", filters],
    queryFn: ({ signal }) => listAuditLogs(filters, signal),
    enabled: options?.enabled,
  })
}

/** GET /v1/audit-logs/{id} — one specific event, by ID. Used for
 * deep-linking (e.g. AuditLogsPage's own `?event=` param, set by the
 * dashboard's Recent Security Activity rows) rather than requiring the
 * target event to already be present in whatever filtered page the list
 * query above happens to be showing. */
export function useAuditLog(id: string | null) {
  return useQuery({
    queryKey: ["audit-logs", "detail", id],
    queryFn: ({ signal }) => getAuditLog(id as string, signal),
    enabled: id !== null,
  })
}
