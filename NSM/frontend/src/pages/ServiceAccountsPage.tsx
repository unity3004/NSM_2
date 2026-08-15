import { useState } from "react"
import { Bot, AlertTriangle, RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { StatusBadge } from "@/components/StatusBadge"
import { useServiceAccounts } from "@/features/serviceAccounts/useServiceAccounts"
import { CreateServiceAccountDialog } from "@/features/serviceAccounts/CreateServiceAccountDialog"
import { ServiceAccountDetailSheet } from "@/features/serviceAccounts/ServiceAccountDetailSheet"
import { SERVICE_ACCOUNT_STATUS_META } from "@/features/serviceAccounts/serviceAccountDisplay"
import { usePermission } from "@/features/auth/usePermission"
import { cn } from "@/lib/utils"

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
  const { data, isLoading, isError, refetch, isRefetching } = useServiceAccounts()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const canCreate = usePermission("service_accounts:create")

  const accounts = data?.data ?? []

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
            <Bot className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Service accounts</h1>
            <p className="text-sm text-muted-foreground">
              Non-human identities for applications and workloads. Grant a role, assign a secret
              policy to that role, and issue a credential — the same authorization chain a human
              user goes through, applied to machine callers.
            </p>
          </div>
        </div>
        {canCreate && <CreateServiceAccountDialog />}
      </div>

      {!isLoading && isError && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-12 text-center">
          <AlertTriangle className="size-5 text-muted-foreground" strokeWidth={1.5} aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-foreground">Unable to load service accounts</p>
            <p className="mt-1 text-sm text-muted-foreground">
              You may not have permission to view service accounts, or something went wrong.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isRefetching}>
            <RefreshCw className={cn("size-3.5", isRefetching && "animate-spin")} />
            {isRefetching ? "Retrying…" : "Retry"}
          </Button>
        </div>
      )}

      {isLoading && (
        <div className="flex flex-col gap-2">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}

      {!isLoading && !isError && accounts.length === 0 && (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-border py-16 text-center">
          <span className="flex size-12 items-center justify-center rounded-full bg-kanz-surface-elevated text-kanz-primary">
            <Bot className="size-5" strokeWidth={1.75} aria-hidden="true" />
          </span>
          <div>
            <p className="text-sm font-medium text-foreground">No service accounts yet</p>
            <p className="mt-1 max-w-xs text-sm text-muted-foreground">
              Create a machine identity for an application or workload to get started.
            </p>
          </div>
        </div>
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
                    <StatusBadge
                      icon={SERVICE_ACCOUNT_STATUS_META[sa.status].icon}
                      label={SERVICE_ACCOUNT_STATUS_META[sa.status].label}
                      className={SERVICE_ACCOUNT_STATUS_META[sa.status].className}
                    />
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
