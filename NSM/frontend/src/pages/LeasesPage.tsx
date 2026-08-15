import { useEffect, useMemo, useState } from "react"
import { Zap, Search, ChevronRight, AlertTriangle, RefreshCw, Database } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useLeases } from "@/features/leases/useLeases"
import { CreateLeaseDialog } from "@/features/leases/CreateLeaseDialog"
import { LeaseDetailSheet } from "@/features/leases/LeaseDetailSheet"
import { LeaseCountdown } from "@/features/leases/LeaseCountdown"
import { LeaseStatusBadge } from "@/features/leases/LeaseStatusBadge"
import { displayStatus, leaseTypeLabel, type DisplayStatus } from "@/features/leases/leaseDisplay"
import { cn } from "@/lib/utils"
import type { LeaseResponse } from "@/types/lease"

const FILTERS: { value: DisplayStatus | "all"; label: string }[] = [
  { value: "all", label: "All" },
  { value: "active", label: "Active" },
  { value: "expiring", label: "Expiring" },
  { value: "expired", label: "Expired" },
  { value: "revoked", label: "Revoked" },
]

/** A coarse (30s) clock used only to keep the summary counts and filter
 * chips reasonably fresh as leases cross into "expiring"/"expired" —
 * deliberately not per-second: each row's own countdown (LeaseCountdown/
 * useCountdown) already ticks live and independently, so this doesn't
 * need to force a full-list re-render every second too, just often
 * enough that the bucket a lease is filed under doesn't visibly go stale
 * during a normal viewing session. */
function usePeriodicNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), intervalMs)
    return () => clearInterval(interval)
  }, [intervalMs])
  return now
}

// REAL API DATA: every row comes from GET /v1/leases — Sprint 5 Task 2's
// dynamic-secret leasing. A lease tracks a temporary, dynamically-issued
// credential's lifecycle only; the credential itself is shown exactly
// once, in CreateLeaseDialog's own creation response, and never appears
// anywhere in this list or its detail view (see LeaseResponse's own doc
// comment). GET /v1/leases requires only authentication: every
// authenticated caller sees their own leases here; a caller who also
// holds leases:read sees every lease in the organization.
export function LeasesPage() {
  const { data, isLoading, isError, refetch, isRefetching } = useLeases()
  const [search, setSearch] = useState("")
  const [filter, setFilter] = useState<DisplayStatus | "all">("all")
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const now = usePeriodicNow(30_000)

  const allLeases = useMemo(() => data?.data ?? [], [data])
  const possiblyTruncated = data ? data.data.length === data.page.limit : false

  const counts = useMemo(() => {
    const result: Record<DisplayStatus, number> = { active: 0, expiring: 0, expired: 0, revoked: 0 }
    for (const lease of allLeases) result[displayStatus(lease, now)] += 1
    return result
  }, [allLeases, now])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return allLeases.filter((lease) => {
      if (filter !== "all" && displayStatus(lease, now) !== filter) return false
      if (!q) return true
      return (
        lease.lease_id.toLowerCase().includes(q) ||
        lease.resource_path.toLowerCase().includes(q) ||
        lease.lease_type.toLowerCase().includes(q) ||
        leaseTypeLabel(lease.lease_type).toLowerCase().includes(q)
      )
    })
  }, [allLeases, search, filter, now])

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
            <Zap className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Leases</h1>
            <p className="text-sm text-muted-foreground">
              Manage temporary credentials, expiration, and controlled access.
            </p>
          </div>
        </div>
        <CreateLeaseDialog />
      </div>

      {!isLoading && !isError && allLeases.length > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <SummaryTile label="Active" value={counts.active} className="text-kanz-success" />
          <SummaryTile label="Expiring Soon" value={counts.expiring} className="text-kanz-warning" />
          <SummaryTile label="Expired" value={counts.expired} className="text-muted-foreground" />
          <SummaryTile label="Revoked" value={counts.revoked} className="text-kanz-danger" />
        </div>
      )}

      <div className="flex flex-col gap-3">
        <div className="relative max-w-sm">
          <Search
            className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            placeholder="Search leases…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            className="pl-8"
            aria-label="Search leases"
          />
        </div>

        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map((f) => (
            <FilterChip key={f.value} label={f.label} active={filter === f.value} onClick={() => setFilter(f.value)} />
          ))}
        </div>
      </div>

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
          <Skeleton className="h-20 w-full" />
        </div>
      )}

      {!isLoading && isError && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-12 text-center">
          <AlertTriangle className="size-5 text-muted-foreground" strokeWidth={1.5} aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-foreground">Unable to load leases</p>
            <p className="mt-1 text-sm text-muted-foreground">KANZ could not retrieve the current lease inventory.</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isRefetching}>
            <RefreshCw className={cn("size-3.5", isRefetching && "animate-spin")} />
            {isRefetching ? "Retrying…" : "Retry"}
          </Button>
        </div>
      )}

      {!isLoading && !isError && allLeases.length === 0 && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-16 text-center">
          <span className="flex size-12 items-center justify-center rounded-full bg-kanz-surface-elevated text-kanz-primary">
            <Zap className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <p className="text-sm font-medium text-foreground">No active leases</p>
            <p className="mt-1 max-w-xs text-sm text-muted-foreground">
              Temporary credentials issued by KANZ will appear here.
            </p>
          </div>
        </div>
      )}

      {!isLoading && !isError && allLeases.length > 0 && filtered.length === 0 && (
        <p className="rounded-lg border border-dashed border-border py-10 text-center text-sm text-muted-foreground">
          No leases match this filter.
        </p>
      )}

      {!isLoading && !isError && filtered.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {filtered.map((lease) => (
            <LeaseRow key={lease.lease_id} lease={lease} onSelect={() => setSelectedId(lease.lease_id)} />
          ))}
          {possiblyTruncated && (
            <p className="text-xs text-muted-foreground">
              Showing the first {allLeases.length} leases — more may exist.
            </p>
          )}
        </div>
      )}

      <LeaseDetailSheet leaseId={selectedId} onOpenChange={(open) => !open && setSelectedId(null)} />
    </div>
  )
}

function SummaryTile({ label, value, className }: { label: string; value: number; className?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-card px-3.5 py-3">
      <span className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{label}</span>
      <span className={cn("font-mono text-2xl font-semibold tracking-tight", className)}>{value}</span>
    </div>
  )
}

function FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "rounded-full border px-2.5 py-1 text-xs font-medium transition-colors duration-150",
        active
          ? "border-kanz-primary/40 bg-kanz-primary/10 text-kanz-primary"
          : "border-border text-muted-foreground hover:border-kanz-primary/25 hover:text-foreground",
      )}
    >
      {label}
    </button>
  )
}

function LeaseRow({ lease, onSelect }: { lease: LeaseResponse; onSelect: () => void }) {
  const status = displayStatus(lease)
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
      <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary transition-colors group-hover:brightness-125">
        <Database className="size-4" strokeWidth={1.75} aria-hidden="true" />
      </span>

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium text-foreground">{leaseTypeLabel(lease.lease_type)}</span>
          <LeaseStatusBadge status={status} className="shrink-0" />
        </div>
        <p className="truncate font-mono text-xs text-muted-foreground">{lease.resource_path}</p>
      </div>

      <div className="w-36 shrink-0">
        <LeaseCountdown lease={lease} showBar={status === "active" || status === "expiring"} />
      </div>

      <ChevronRight
        className="size-4 shrink-0 text-muted-foreground transition-[transform,color] duration-150 group-hover:translate-x-0.5 group-hover:text-kanz-primary"
        aria-hidden="true"
      />
    </button>
  )
}
