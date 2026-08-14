import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { History } from "lucide-react"
import { useAuditLogs } from "@/features/audit/useAuditLogs"
import { formatRelativeTime } from "@/lib/utils"
import type { AuditResult } from "@/types/audit"

function resultBadgeVariant(result: AuditResult): "outline" | "destructive" | "secondary" {
  switch (result) {
    case "success":
      return "outline"
    case "denied":
    case "failure":
      return "destructive"
    default:
      return "secondary"
  }
}

/**
 * REAL API DATA: GET /v1/audit-logs (audit:read-gated), limit: 5, the same
 * tamper-evident trail AuditLogsPage's own full table reads from — sorted
 * occurred_at DESC server-side (audit_repository.go), so the first five
 * rows genuinely are the most recent events, not an assumption made here.
 *
 * This supersedes the earlier RecentActivityPlaceholder: that component's
 * own doc comment said no HTTP route exposed audit_logs yet, which was
 * true when it was written but is no longer — GET /v1/audit-logs has
 * existed since Sprint 4 Task 3. A user without audit:read gets the same
 * real 403 AuditLogsPage's own isError branch already shows, not a
 * redesigned permission check.
 */
export function RecentAuditEvents() {
  const { data, isLoading, isError } = useAuditLogs({ limit: 5 })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent activity</CardTitle>
        <CardDescription>The five most recent audit events.</CardDescription>
      </CardHeader>
      <CardContent>
        {isLoading && (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        )}

        {isError && (
          <p className="text-sm text-muted-foreground">
            You don't have permission to view audit events, or something went wrong.
          </p>
        )}

        {data && data.data.length === 0 && (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-10 text-center text-sm text-muted-foreground">
            <History className="size-5" strokeWidth={1.5} />
            <p>No audit events yet.</p>
          </div>
        )}

        {data && data.data.length > 0 && (
          <div className="flex flex-col gap-3">
            {data.data.map((event) => (
              <div key={event.id} className="flex items-center justify-between gap-3 text-sm">
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="truncate font-mono text-xs font-medium">{event.action}</span>
                  <span className="text-xs text-muted-foreground">
                    {formatRelativeTime(event.occurred_at)}
                  </span>
                </div>
                <Badge variant={resultBadgeVariant(event.result)} className="shrink-0 text-xs">
                  {event.result}
                </Badge>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
