import { useEffect, useMemo, useState } from "react"
import { useSearchParams } from "react-router-dom"
import {
  Radar,
  Search,
  AlertTriangle,
  RefreshCw,
  ShieldCheck,
  X,
} from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useAuditLog, useAuditLogs } from "@/features/audit/useAuditLogs"
import { AuditEventDetailSheet } from "@/features/audit/AuditEventDetailSheet"
import { useUsers } from "@/features/users/useUsers"
import { useServiceAccounts } from "@/features/serviceAccounts/useServiceAccounts"
import {
  actorLabel,
  resourceTypeAndPath,
  iconForAction,
  RESULT_META,
} from "@/features/dashboard/auditDisplay"
import { cn, formatRelativeTime } from "@/lib/utils"
import type { AuditLogFilters, AuditLogResponse, AuditResult } from "@/types/audit"

const FILTER_LABELS: Record<keyof AuditLogFilters, string> = {
  actor_type: "Actor type",
  actor_id: "Identity",
  action: "Action",
  resource_type: "Resource type",
  resource_id: "Resource ID / path",
  result: "Status",
  request_id: "Request ID",
  occurred_after: "From",
  occurred_before: "To",
  limit: "Limit",
  cursor: "Cursor",
}

const CHIP_KEYS: (keyof AuditLogFilters)[] = [
  "action",
  "actor_id",
  "resource_type",
  "resource_id",
  "result",
  "request_id",
  "occurred_after",
  "occurred_before",
]

function emptyFilters(): AuditLogFilters {
  return { limit: 25 }
}

// REAL API DATA: every row and every summary count comes from
// GET /v1/audit-logs (audit:read-gated, Sprint 4 Task 3) — the same
// tamper-evident, hash-chained trail every other security-relevant action
// in this application writes to. This page only reads; there is no edit or
// delete control anywhere here because no such backend API exists (see
// AuditLogRepository's own "append-only" doc comment) — that is enforced
// server-side, not merely hidden client-side.
export function AuditLogsPage() {
  const [draftFilters, setDraftFilters] = useState<AuditLogFilters>(emptyFilters())
  const [appliedFilters, setAppliedFilters] = useState<AuditLogFilters>(emptyFilters())
  const [pages, setPages] = useState<AuditLogResponse[][]>([])
  const [selectedEvent, setSelectedEvent] = useState<AuditLogResponse | null>(null)
  const [searchParams, setSearchParams] = useSearchParams()

  const { data, isLoading, isFetching, isError, refetch } = useAuditLogs(appliedFilters)
  const users = useUsers()
  const serviceAccounts = useServiceAccounts()

  // A fresh filter set replaces accumulated pages; a cursor-advance
  // (Load more) appends to them. Both go through appliedFilters changing,
  // distinguished by whether the incoming page's own filters carry the
  // cursor this component itself set below.
  useEffect(() => {
    if (!data) return
    setPages((prev) => (appliedFilters.cursor ? [...prev, data.data] : [data.data]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data])

  // Deep-link support: /audit?event=<id> (e.g. from the dashboard's
  // Recent Security Activity rows) opens that one event's detail sheet
  // directly via GET /v1/audit-logs/{id} — real backend functionality
  // that already existed but had no client call to it before now — no
  // dependency on the target event already being present in whatever
  // filtered page/list this component happens to be showing.
  const deepLinkedEventId = searchParams.get("event")
  const deepLinkedEvent = useAuditLog(deepLinkedEventId)
  useEffect(() => {
    if (!deepLinkedEvent.data) return
    setSelectedEvent(deepLinkedEvent.data)
    const next = new URLSearchParams(searchParams)
    next.delete("event")
    setSearchParams(next, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deepLinkedEvent.data])

  function applyFilters(next: AuditLogFilters = draftFilters) {
    setPages([])
    setDraftFilters(next)
    setAppliedFilters({ ...next, cursor: undefined })
  }

  function clearFilters() {
    applyFilters(emptyFilters())
  }

  function removeFilter(key: keyof AuditLogFilters) {
    applyFilters({ ...draftFilters, [key]: undefined })
  }

  function applyTimePreset(hours: number) {
    applyFilters({
      ...draftFilters,
      occurred_after: new Date(Date.now() - hours * 60 * 60 * 1000).toISOString(),
      occurred_before: undefined,
    })
  }

  function loadMore() {
    if (!data?.page.next_cursor) return
    setAppliedFilters({ ...appliedFilters, cursor: data.page.next_cursor })
  }

  const rows = pages.flat()
  const activeChips = CHIP_KEYS.filter((key) => appliedFilters[key] !== undefined && appliedFilters[key] !== "")
  const hasAnyFilters = activeChips.length > 0
  const usersData = users.data?.data
  const serviceAccountsData = serviceAccounts.data?.data

  const identityOptions = useMemo(() => {
    const humans = (usersData ?? []).map((u) => ({ id: u.id, label: u.email, type: "Human" }))
    const machines = (serviceAccountsData ?? []).map((sa) => ({ id: sa.id, label: sa.name, type: "Machine" }))
    return [...humans, ...machines]
  }, [usersData, serviceAccountsData])

  function chipValueLabel(key: keyof AuditLogFilters, value: string): string {
    if (key === "actor_id") {
      const identity = identityOptions.find((i) => i.id === value)
      return identity ? identity.label : value
    }
    if (key === "occurred_after" || key === "occurred_before") return new Date(value).toLocaleString()
    return value
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
            <Radar className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Audit Explorer</h1>
            <p className="text-sm text-muted-foreground">
              Investigate security activity across your KANZ environment.
            </p>
          </div>
        </div>
        {!isLoading && !isError && data && (
          <span className="flex shrink-0 items-center gap-1.5 text-xs font-medium text-kanz-success">
            <ShieldCheck className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
            Audit trail operational
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <SummaryCard label="Total" value={data?.summary.total ?? 0} />
        <SummaryCard label="Successful" value={data?.summary.success ?? 0} className="text-kanz-success" />
        <SummaryCard label="Failed" value={data?.summary.failure ?? 0} className="text-kanz-danger" />
        <SummaryCard label="Denied" value={data?.summary.denied ?? 0} className="text-kanz-warning" />
      </div>

      <div className="flex flex-col gap-4 rounded-lg border border-border bg-card p-4">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-action">Action</Label>
            <Input
              id="filter-action"
              placeholder="secret.read"
              className="font-mono"
              value={draftFilters.action ?? ""}
              onChange={(e) => setDraftFilters((f) => ({ ...f, action: e.target.value || undefined }))}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-status">Status</Label>
            <Select
              value={draftFilters.result ?? "any"}
              onValueChange={(value) =>
                setDraftFilters((f) => ({ ...f, result: value === "any" ? undefined : (value as AuditResult) }))
              }
            >
              <SelectTrigger id="filter-status" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="any">All statuses</SelectItem>
                <SelectItem value="success">Success</SelectItem>
                <SelectItem value="failure">Failure</SelectItem>
                <SelectItem value="denied">Denied</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-identity">Identity</Label>
            <Select
              value={draftFilters.actor_id ?? "any"}
              onValueChange={(value) =>
                setDraftFilters((f) => ({ ...f, actor_id: value === "any" ? undefined : value }))
              }
            >
              <SelectTrigger id="filter-identity" className="w-full">
                <SelectValue placeholder="All identities" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="any">All identities</SelectItem>
                {identityOptions.map((identity) => (
                  <SelectItem key={identity.id} value={identity.id}>
                    {identity.label} ({identity.type})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-resource-type">Resource type</Label>
            <Input
              id="filter-resource-type"
              placeholder="secret"
              className="font-mono"
              value={draftFilters.resource_type ?? ""}
              onChange={(e) => setDraftFilters((f) => ({ ...f, resource_type: e.target.value || undefined }))}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-resource-id">Resource ID / path</Label>
            <div className="relative">
              <Search
                className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground"
                aria-hidden="true"
              />
              <Input
                id="filter-resource-id"
                placeholder="prod/db/password"
                className="pl-7 font-mono"
                value={draftFilters.resource_id ?? ""}
                onChange={(e) => setDraftFilters((f) => ({ ...f, resource_id: e.target.value || undefined }))}
              />
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-request-id">Request ID</Label>
            <Input
              id="filter-request-id"
              placeholder="req_..."
              className="font-mono"
              value={draftFilters.request_id ?? ""}
              onChange={(e) => setDraftFilters((f) => ({ ...f, request_id: e.target.value || undefined }))}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-after">From</Label>
            <Input
              id="filter-after"
              type="datetime-local"
              value={draftFilters.occurred_after?.slice(0, 16) ?? ""}
              onChange={(e) =>
                setDraftFilters((f) => ({
                  ...f,
                  occurred_after: e.target.value ? new Date(e.target.value).toISOString() : undefined,
                }))
              }
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="filter-before">To</Label>
            <Input
              id="filter-before"
              type="datetime-local"
              value={draftFilters.occurred_before?.slice(0, 16) ?? ""}
              onChange={(e) =>
                setDraftFilters((f) => ({
                  ...f,
                  occurred_before: e.target.value ? new Date(e.target.value).toISOString() : undefined,
                }))
              }
            />
          </div>

          <div className="flex flex-col gap-1.5 justify-self-start">
            <Label>Quick range</Label>
            <div className="flex gap-1.5">
              <Button type="button" variant="outline" size="sm" onClick={() => applyTimePreset(24)}>
                24h
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={() => applyTimePreset(24 * 7)}>
                7d
              </Button>
              <Button type="button" variant="outline" size="sm" onClick={() => applyTimePreset(24 * 30)}>
                30d
              </Button>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button size="sm" onClick={() => applyFilters()} disabled={isFetching}>
            Apply filters
          </Button>
          <Button size="sm" variant="ghost" onClick={clearFilters} disabled={isFetching || !hasAnyFilters}>
            Clear
          </Button>
        </div>

        {hasAnyFilters && (
          <div className="flex flex-wrap gap-1.5 border-t border-border pt-3">
            {activeChips.map((key) => (
              <button
                key={key}
                type="button"
                onClick={() => removeFilter(key)}
                className="flex items-center gap-1 rounded-full border border-kanz-primary/30 bg-kanz-primary/10 px-2.5 py-1 text-xs font-medium text-kanz-primary transition-colors hover:border-kanz-primary/50"
              >
                {FILTER_LABELS[key]}: {chipValueLabel(key, String(appliedFilters[key]))}
                <X className="size-3" aria-hidden="true" />
              </button>
            ))}
          </div>
        )}
      </div>

      {!isLoading && isError && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-12 text-center">
          <AlertTriangle className="size-5 text-muted-foreground" strokeWidth={1.5} aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-foreground">Unable to load audit events</p>
            <p className="mt-1 text-sm text-muted-foreground">KANZ could not retrieve the audit trail.</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn("size-3.5", isFetching && "animate-spin")} />
            {isFetching ? "Retrying…" : "Retry"}
          </Button>
        </div>
      )}

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      )}

      {!isLoading && !isError && rows.length === 0 && !hasAnyFilters && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-16 text-center">
          <span className="flex size-12 items-center justify-center rounded-full bg-kanz-surface-elevated text-kanz-primary">
            <Radar className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <p className="text-sm font-medium text-foreground">No audit events found</p>
            <p className="mt-1 max-w-xs text-sm text-muted-foreground">
              Try adjusting your filters or search criteria.
            </p>
          </div>
        </div>
      )}

      {!isLoading && !isError && rows.length === 0 && hasAnyFilters && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-16 text-center">
          <div>
            <p className="text-sm font-medium text-foreground">No matching events</p>
            <p className="mt-1 max-w-xs text-sm text-muted-foreground">
              No audit events match the current investigation filters.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={clearFilters}>
            Clear filters
          </Button>
        </div>
      )}

      {!isLoading && !isError && rows.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {rows.map((event) => (
            <EventRow
              key={event.id}
              event={event}
              users={usersData}
              serviceAccounts={serviceAccountsData}
              onSelect={() => setSelectedEvent(event)}
            />
          ))}

          <div className="flex items-center justify-between pt-1">
            <p className="text-xs text-muted-foreground">
              Showing {rows.length.toLocaleString()} of {(data?.summary.total ?? 0).toLocaleString()} events
            </p>
            {data?.page.has_more && (
              <Button variant="outline" size="sm" onClick={loadMore} disabled={isFetching}>
                {isFetching ? "Loading…" : "Load more"}
              </Button>
            )}
          </div>
        </div>
      )}

      <AuditEventDetailSheet
        event={selectedEvent}
        users={usersData}
        serviceAccounts={serviceAccountsData}
        onOpenChange={(open) => {
          if (!open) setSelectedEvent(null)
        }}
      />
    </div>
  )
}

function SummaryCard({ label, value, className }: { label: string; value: number; className?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-card px-3.5 py-3">
      <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{label}</span>
      <span className={cn("font-mono text-2xl font-semibold tracking-tight", className)}>
        {value.toLocaleString()}
      </span>
    </div>
  )
}

function EventRow({
  event,
  users,
  serviceAccounts,
  onSelect,
}: {
  event: AuditLogResponse
  users: Parameters<typeof actorLabel>[1]
  serviceAccounts: Parameters<typeof actorLabel>[2]
  onSelect: () => void
}) {
  const ActionIcon = iconForAction(event.action)
  const result = RESULT_META[event.result]
  const actor = actorLabel(event, users, serviceAccounts)
  const resource = resourceTypeAndPath(event)

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        "group flex w-full items-center gap-3 rounded-lg border border-border bg-card px-3.5 py-3 text-left",
        "transition-[border-color,background-color,transform] duration-150",
        "hover:border-kanz-primary/30 hover:bg-kanz-surface-elevated",
      )}
    >
      <ActionIcon
        className="size-4 shrink-0 text-kanz-primary transition-colors group-hover:brightness-125"
        strokeWidth={1.75}
        aria-hidden="true"
      />

      <div className="min-w-0 flex-1">
        <p className="truncate font-mono text-sm font-medium text-foreground">{event.action}</p>
        <p className="truncate text-xs text-muted-foreground">
          {actor}
          {resource && ` · ${resource}`}
        </p>
        <p className="text-[0.65rem] text-muted-foreground">
          {formatRelativeTime(event.occurred_at)}
          {event.request_id && (
            <span className="font-mono"> · Request ID: {event.request_id.slice(0, 8)}…</span>
          )}
        </p>
      </div>

      <span className={cn("flex shrink-0 items-center gap-1 text-xs font-semibold tracking-wide", result.className)}>
        <result.icon className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
        {result.label}
      </span>
    </button>
  )
}
