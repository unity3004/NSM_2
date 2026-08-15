// Mirrors auth-service/internal/dto/audit.go exactly — Sprint 4 Task 3's
// security audit trail, read-only from this client's perspective: there
// is no create/update/delete request type here because no such API
// exists on the backend (see AuditLogRepository's own "append-only, no
// Update or Delete method" doc comment) — audit_logs rows are written
// exclusively by the backend itself, as a side effect of other actions.

import type { PageMeta } from "@/types/common"

export type AuditActorType = "user" | "service_account" | "api_key" | "system"
export type AuditResult = "success" | "failure" | "denied"

/** GET /v1/audit-logs' row shape. PrevHash/RecordHash are the
 * tamper-evident hash chain (see migrations/000018's own doc comment) —
 * exposed so an admin or an external integrity job can independently
 * verify it, not because this UI itself re-verifies the chain. */
export interface AuditLogResponse {
  id: string
  organization_id?: string | null
  actor_type: AuditActorType
  actor_id?: string | null
  action: string
  resource_type?: string | null
  resource_id?: string | null
  result: AuditResult
  ip_address?: string | null
  request_id?: string | null
  metadata?: Record<string, unknown>
  prev_hash?: string | null
  record_hash: string
  occurred_at: string
}

/** GET /v1/audit-logs' own "summary" field — Total/Successful/Failed/
 * Denied, computed server-side across every row the request's filters
 * match, not merely the one page of `data` returned alongside it. See
 * dto.AuditLogSummary's own doc comment. */
export interface AuditLogSummary {
  total: number
  success: number
  failure: number
  denied: number
}

/** GET /v1/audit-logs' own list.data/list.page (dto.PageMeta) is the
 * generic services/httpClient ListResponse<T> already covers — the
 * summary field is the one thing that shape doesn't have, since no other
 * list endpoint returns one. */
export interface AuditLogListResponse {
  data: AuditLogResponse[]
  page: PageMeta
  summary: AuditLogSummary
}

/** GET /v1/audit-logs' query parameters — every field optional, applied
 * server-side as an AND filter (see repository.AuditLogFilter's own doc
 * comment). Never constructed directly into a query string by this
 * client; see services/auditApi.ts's own buildAuditLogQuery. */
export interface AuditLogFilters {
  actor_type?: AuditActorType
  actor_id?: string
  action?: string
  resource_type?: string
  resource_id?: string
  result?: AuditResult
  request_id?: string
  occurred_after?: string
  occurred_before?: string
  limit?: number
  cursor?: string
}
