import { useEffect, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useAuditLogs } from "@/features/audit/useAuditLogs"
import type { AuditLogFilters, AuditLogResponse, AuditResult } from "@/types/audit"

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

// REAL API DATA: every row comes from GET /v1/audit-logs (audit:read-gated,
// Sprint 4 Task 3) — the same tamper-evident, hash-chained trail every
// other security-relevant action in this application writes to. This page
// only reads; there is no edit or delete control anywhere here because no
// such backend API exists (see AuditLogRepository's own "append-only" doc
// comment) — that is enforced server-side, not merely hidden client-side.
export function AuditLogsPage() {
  const [draftFilters, setDraftFilters] = useState<AuditLogFilters>({ limit: 25 })
  const [appliedFilters, setAppliedFilters] = useState<AuditLogFilters>({ limit: 25 })
  const [pages, setPages] = useState<AuditLogResponse[][]>([])

  const { data, isLoading, isFetching, isError } = useAuditLogs(appliedFilters)

  // A fresh filter set replaces accumulated pages; a cursor-advance
  // (Load more) appends to them. Both go through appliedFilters changing,
  // distinguished by whether the incoming page's own filters carry the
  // cursor this component itself set below.
  useEffect(() => {
    if (!data) return
    setPages((prev) => (appliedFilters.cursor ? [...prev, data.data] : [data.data]))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data])

  function applyFilters() {
    setPages([])
    setAppliedFilters({ ...draftFilters, cursor: undefined })
  }

  function loadMore() {
    if (!data?.page.next_cursor) return
    setAppliedFilters({ ...appliedFilters, cursor: data.page.next_cursor })
  }

  const rows = pages.flat()

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit Logs</h1>
        <p className="text-sm text-muted-foreground">
          A tamper-evident, hash-chained record of security-relevant events. Every filter below is
          applied server-side; results are never fetched unbounded.
        </p>
      </div>

      <div className="flex flex-wrap items-end gap-3 rounded-lg border p-4">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="filter-action">Action</Label>
          <Input
            id="filter-action"
            placeholder="secret.read"
            className="w-48 font-mono"
            value={draftFilters.action ?? ""}
            onChange={(e) => setDraftFilters((f) => ({ ...f, action: e.target.value || undefined }))}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="filter-actor">Actor ID</Label>
          <Input
            id="filter-actor"
            placeholder="user id"
            className="w-48 font-mono"
            value={draftFilters.actor_id ?? ""}
            onChange={(e) => setDraftFilters((f) => ({ ...f, actor_id: e.target.value || undefined }))}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="filter-resource">Resource type</Label>
          <Input
            id="filter-resource"
            placeholder="secret"
            className="w-40 font-mono"
            value={draftFilters.resource_type ?? ""}
            onChange={(e) => setDraftFilters((f) => ({ ...f, resource_type: e.target.value || undefined }))}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label>Result</Label>
          <Select
            value={draftFilters.result ?? "any"}
            onValueChange={(value) =>
              setDraftFilters((f) => ({ ...f, result: value === "any" ? undefined : (value as AuditResult) }))
            }
          >
            <SelectTrigger className="w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="any">Any</SelectItem>
              <SelectItem value="success">Success</SelectItem>
              <SelectItem value="failure">Failure</SelectItem>
              <SelectItem value="denied">Denied</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button size="sm" onClick={applyFilters} disabled={isFetching}>
          Apply filters
        </Button>
      </div>

      {isError && (
        <p className="text-sm text-muted-foreground">
          You don't have permission to view audit logs, or something went wrong.
        </p>
      )}

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}

      {!isLoading && !isError && (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Result</TableHead>
                <TableHead>Request ID</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-sm text-muted-foreground">
                    No matching events.
                  </TableCell>
                </TableRow>
              )}
              {rows.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                    {new Date(e.occurred_at).toLocaleString()}
                  </TableCell>
                  <TableCell className="font-mono text-xs font-medium">{e.action}</TableCell>
                  <TableCell className="max-w-40 truncate font-mono text-xs">
                    {e.actor_id ?? <span className="text-muted-foreground">system</span>}
                  </TableCell>
                  <TableCell className="max-w-56 truncate font-mono text-xs">
                    {e.resource_type ?? "—"}
                    {e.resource_id ? `: ${e.resource_id}` : ""}
                  </TableCell>
                  <TableCell>
                    <Badge variant={resultBadgeVariant(e.result)} className="text-xs">
                      {e.result}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-32 truncate font-mono text-xs text-muted-foreground">
                    {e.request_id ?? "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      {!isLoading && !isError && data?.page.has_more && (
        <Button variant="outline" size="sm" onClick={loadMore} disabled={isFetching} className="self-start">
          {isFetching ? "Loading…" : "Load more"}
        </Button>
      )}
    </div>
  )
}
