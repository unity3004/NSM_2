import { Link } from "react-router-dom"
import { History, RefreshCw, ArrowRight } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useAuditLogs } from "@/features/audit/useAuditLogs"
import { useUsers } from "@/features/users/useUsers"
import { useServiceAccounts } from "@/features/serviceAccounts/useServiceAccounts"
import { actorLabel, resourceLabel, iconForAction, RESULT_META } from "@/features/dashboard/auditDisplay"
import { formatRelativeTime } from "@/lib/utils"
import { cn } from "@/lib/utils"
import type { AuditLogResponse } from "@/types/audit"

/**
 * "Recent Security Activity" — reuses the identical GET /v1/audit-logs
 * query (useAuditLogs({ limit: 5 })) PrimaryMetrics' and
 * SecurityStatusPanel's own reads also issue, plus the useUsers/
 * useServiceAccounts queries PrimaryMetrics already fetches (for
 * resolving actor IDs to real emails/names — see auditDisplay.ts) — every
 * one of these is a shared TanStack Query cache entry, so this section
 * costs zero extra requests beyond what the dashboard already makes.
 *
 * Each row is a real Link to /audit?event=<id> — AuditLogsPage reads that
 * param and opens the matching event's detail sheet via the existing
 * (newly wired, previously unused by any client) GET /v1/audit-logs/{id}
 * route, so opaque IDs stay one click away rather than being the primary
 * display here.
 */
export function SecurityActivityTimeline() {
  const { data, isLoading, isError, refetch, isRefetching } = useAuditLogs({ limit: 5 })
  const users = useUsers()
  const serviceAccounts = useServiceAccounts()

  return (
    <Card>
      <CardHeader className="flex flex-row items-baseline justify-between gap-4">
        <div>
          <CardTitle>Recent Security Activity</CardTitle>
          <p className="mt-0.5 text-sm text-muted-foreground">
            Five most recent events from your tamper-evident audit trail.
          </p>
        </div>
        <Link
          to="/audit"
          className="flex shrink-0 items-center gap-1 text-sm font-medium text-kanz-primary transition-colors hover:text-kanz-primary-glow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kanz-primary/50"
        >
          View all
          <ArrowRight className="size-3.5" aria-hidden="true" />
        </Link>
      </CardHeader>
      <CardContent>
        {isLoading && (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        )}

        {!isLoading && isError && (
          <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-10 text-center">
            <p className="text-sm text-muted-foreground">Unable to load security activity.</p>
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isRefetching}>
              <RefreshCw className={cn("size-3.5", isRefetching && "animate-spin")} />
              {isRefetching ? "Retrying…" : "Retry"}
            </Button>
          </div>
        )}

        {!isLoading && !isError && data && data.data.length === 0 && (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-border py-10 text-center text-sm text-muted-foreground">
            <History className="size-5" strokeWidth={1.5} aria-hidden="true" />
            <p>No recent security events.</p>
          </div>
        )}

        {!isLoading && !isError && data && data.data.length > 0 && (
          <ul className="flex flex-col gap-0.5">
            {data.data.map((event) => (
              <EventRow key={event.id} event={event} users={users.data?.data} serviceAccounts={serviceAccounts.data?.data} />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function EventRow({
  event,
  users,
  serviceAccounts,
}: {
  event: AuditLogResponse
  users: Parameters<typeof actorLabel>[1]
  serviceAccounts: Parameters<typeof actorLabel>[2]
}) {
  const ActionIcon = iconForAction(event.action)
  const result = RESULT_META[event.result]
  const actor = actorLabel(event, users, serviceAccounts)
  const resource = resourceLabel(event)

  return (
    <li>
      <Link
        to={`/audit?event=${encodeURIComponent(event.id)}`}
        className={cn(
          "flex flex-col gap-1 rounded-lg border border-transparent px-2.5 py-2.5",
          "transition-colors duration-150 hover:border-border hover:bg-kanz-surface-elevated/60",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-kanz-primary/50",
        )}
      >
        <div className="flex items-center gap-2">
          <ActionIcon className="size-4 shrink-0 text-kanz-primary" strokeWidth={1.75} aria-hidden="true" />
          <span className="min-w-0 flex-1 truncate font-mono text-xs font-medium text-foreground">
            {event.action}
          </span>
          <span className={cn("flex shrink-0 items-center gap-1 text-xs font-semibold tracking-wide", result.className)}>
            <result.icon className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            {result.label}
          </span>
        </div>
        <div className="pl-6">
          <p className="truncate text-xs text-muted-foreground">
            {actor}
            {resource && ` · ${resource}`}
          </p>
          <p className="text-[0.65rem] text-muted-foreground">{formatRelativeTime(event.occurred_at)}</p>
        </div>
      </Link>
    </li>
  )
}
