import { useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useLeases } from "@/features/leases/useLeases"
import { CreateLeaseDialog } from "@/features/leases/CreateLeaseDialog"
import { LeaseDetailSheet } from "@/features/leases/LeaseDetailSheet"
import type { LeaseStatus } from "@/types/lease"

function formatDate(value?: string | null): string {
  if (!value) return "—"
  return new Date(value).toLocaleString()
}

function statusVariant(status: LeaseStatus): "outline" | "destructive" | "secondary" {
  if (status === "active") return "outline"
  if (status === "revoked") return "destructive"
  return "secondary"
}

// REAL API DATA: every row comes from GET /v1/leases — Sprint 5 Task 2's
// dynamic-secret leasing. A lease tracks a temporary, dynamically-issued
// credential's lifecycle only; the credential itself is shown exactly
// once, in CreateLeaseDialog's own creation response, and never appears
// anywhere in this list or its detail view (see LeaseResponse's own doc
// comment) — the same "never re-expose credential material through a
// normal read endpoint" guarantee ServiceAccountsPage already establishes
// for API-key secrets. GET /v1/leases requires only authentication: every
// authenticated caller sees their own leases here; a caller who also
// holds leases:read sees every lease in the organization.
export function LeasesPage() {
  const { data, isLoading, isError } = useLeases()
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const leases = data?.data ?? []

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Leases</h1>
          <p className="text-sm text-muted-foreground">
            Temporary, dynamically-issued credentials with a bounded lifetime. Each lease's
            credential is shown once, at creation — revoke a lease to invalidate it immediately.
          </p>
        </div>
        <CreateLeaseDialog />
      </div>

      {isError && (
        <p className="text-sm text-muted-foreground">
          Something went wrong loading your leases.
        </p>
      )}

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}

      {!isLoading && !isError && leases.length === 0 && (
        <p className="text-sm text-muted-foreground">No leases yet.</p>
      )}

      {!isLoading && !isError && leases.length > 0 && (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Lease ID</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Resource</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>TTL</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Expires</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {leases.map((lease) => (
                <TableRow
                  key={lease.lease_id}
                  className="cursor-pointer"
                  onClick={() => setSelectedId(lease.lease_id)}
                >
                  <TableCell className="max-w-[10rem] truncate font-mono text-xs">
                    {lease.lease_id}
                  </TableCell>
                  <TableCell>{lease.lease_type}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">
                    {lease.resource_path}
                  </TableCell>
                  <TableCell>
                    <Badge variant={statusVariant(lease.status)} className="text-xs">
                      {lease.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{lease.ttl}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(lease.created_at)}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(lease.expires_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <LeaseDetailSheet leaseId={selectedId} onOpenChange={(open) => !open && setSelectedId(null)} />
    </div>
  )
}
