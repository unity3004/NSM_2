import { useQuery } from "@tanstack/react-query"
import { listAuditLogs } from "@/services/auditApi"
import type { AuditLogFilters } from "@/types/audit"

/** One page of audit_logs, refetched whenever filters (including cursor)
 * change — the caller (AuditLogsPage) owns accumulating pages across a
 * "Load more" click and resetting on filter change, the same
 * "the hook fetches one page, the page component owns pagination state"
 * split this codebase has no prior paginated-list precedent to follow
 * more closely (every existing list page hardcodes has_more: false — see
 * secretsApi.ts's own comment on why). */
export function useAuditLogs(filters: AuditLogFilters) {
  return useQuery({
    queryKey: ["audit-logs", filters],
    queryFn: ({ signal }) => listAuditLogs(filters, signal),
  })
}
