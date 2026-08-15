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
import { useServiceAccounts } from "@/features/serviceAccounts/useServiceAccounts"
import { CreateServiceAccountDialog } from "@/features/serviceAccounts/CreateServiceAccountDialog"
import { ServiceAccountDetailSheet } from "@/features/serviceAccounts/ServiceAccountDetailSheet"
import { usePermission } from "@/features/auth/usePermission"

function formatDate(value?: string | null): string {
  if (!value) return "Never"
  return new Date(value).toLocaleString()
}

// REAL API DATA: every row comes from GET /v1/service-accounts
// (service_accounts:read-gated) — Sprint 5 Task 1's machine-identity
// foundation. A service account represents an application or workload,
// not a human: it authenticates by exchanging an API key credential for a
// short-lived access token (POST /v1/service-accounts/{id}/token), never
// through the human login flow, and is authorized through the exact same
// role -> permission -> path-policy chain a human user goes through.
export function ServiceAccountsPage() {
  const { data, isLoading, isError } = useServiceAccounts()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const canCreate = usePermission("service_accounts:create")

  const accounts = data?.data ?? []

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Service accounts</h1>
          <p className="text-sm text-muted-foreground">
            Non-human identities for applications and workloads. Grant a role, assign a secret
            policy to that role, and issue a credential — the same authorization chain a human
            user goes through, applied to machine callers.
          </p>
        </div>
        {canCreate && <CreateServiceAccountDialog />}
      </div>

      {isError && (
        <p className="text-sm text-muted-foreground">
          You don't have permission to view service accounts, or something went wrong.
        </p>
      )}

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}

      {!isLoading && !isError && accounts.length === 0 && (
        <p className="text-sm text-muted-foreground">No service accounts yet.</p>
      )}

      {!isLoading && !isError && accounts.length > 0 && (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last authenticated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {accounts.map((sa) => (
                <TableRow key={sa.id} className="cursor-pointer" onClick={() => setSelectedId(sa.id)}>
                  <TableCell className="font-medium">{sa.name}</TableCell>
                  <TableCell className="max-w-xs truncate text-muted-foreground">
                    {sa.description ?? "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={sa.status === "active" ? "outline" : "destructive"} className="text-xs">
                      {sa.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(sa.created_at)}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDate(sa.last_authenticated_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <ServiceAccountDetailSheet
        serviceAccountId={selectedId}
        onOpenChange={(open) => !open && setSelectedId(null)}
      />
    </div>
  )
}
