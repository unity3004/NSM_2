import { Fragment, useState, type ReactNode } from "react"
import { Link } from "react-router-dom"
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useLease } from "@/features/leases/useLeases"
import { useRenewLease, useRevokeLease } from "@/features/leases/useLeaseMutations"
import { useAuditLogs } from "@/features/audit/useAuditLogs"
import { useUsers } from "@/features/users/useUsers"
import { useServiceAccounts } from "@/features/serviceAccounts/useServiceAccounts"
import { actorLabel } from "@/features/dashboard/auditDisplay"
import { LeaseCountdown } from "@/features/leases/LeaseCountdown"
import { LeaseStatusBadge } from "@/features/leases/LeaseStatusBadge"
import { displayStatus, leaseTypeLabel, type DisplayStatus } from "@/features/leases/leaseDisplay"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { formatRelativeTime, cn } from "@/lib/utils"
import { RotateCw, ShieldOff, History, ArrowRight, KeyRound, Zap } from "lucide-react"
import { toast } from "sonner"

function formatDate(value?: string | null): string {
  if (!value) return "—"
  return new Date(value).toLocaleString()
}

const LIFECYCLE_STEPS: { status: DisplayStatus; label: string }[] = [
  { status: "active", label: "Active" },
  { status: "expiring", label: "Expiring" },
  { status: "expired", label: "Expired" },
]

function LeaseLifecycle({ status }: { status: DisplayStatus }) {
  if (status === "revoked") {
    return (
      <div className="flex items-center gap-2">
        <LifecycleNode label="Active" state="done" />
        <LifecycleConnector />
        <LifecycleNode label="Revoked" state="current" tone="danger" />
      </div>
    )
  }

  const currentIndex = LIFECYCLE_STEPS.findIndex((s) => s.status === status)

  return (
    <div className="flex items-center gap-2">
      <LifecycleNode label="Issued" state="done" />
      <LifecycleConnector />
      {LIFECYCLE_STEPS.map((step, i) => (
        <Fragment key={step.status}>
          <LifecycleNode
            label={step.label}
            state={i < currentIndex ? "done" : i === currentIndex ? "current" : "future"}
            tone={step.status === "expiring" ? "warning" : undefined}
          />
          {i < LIFECYCLE_STEPS.length - 1 && <LifecycleConnector />}
        </Fragment>
      ))}
    </div>
  )
}

function LifecycleNode({
  label,
  state,
  tone,
}: {
  label: string
  state: "done" | "current" | "future"
  tone?: "warning" | "danger"
}) {
  return (
    <div className="flex flex-col items-center gap-1">
      <span
        className={cn(
          "size-2 rounded-full",
          state === "future" && "bg-border",
          state === "done" && "bg-kanz-primary/50",
          state === "current" && tone === "danger" && "bg-kanz-danger",
          state === "current" && tone === "warning" && "bg-kanz-warning",
          state === "current" && !tone && "bg-kanz-primary",
        )}
      />
      <span
        className={cn(
          "text-[0.65rem] tracking-wide uppercase",
          state === "future" ? "text-muted-foreground/50" : "text-muted-foreground",
          state === "current" && "font-medium text-foreground",
        )}
      >
        {label}
      </span>
    </div>
  )
}

function LifecycleConnector() {
  return <div className="h-px w-6 shrink-0 bg-border" aria-hidden="true" />
}

/**
 * Metadata only — GET /v1/leases/{id} never returns credential material,
 * and this component has no field it could render even if the response
 * somehow carried one (see LeaseResponse's own doc comment). The one time
 * a lease's credential is ever shown is CreateLeaseDialog's own creation
 * response, never this page — the "Credential" section below is an
 * honest explanation of that, not a fake Reveal control the API can't
 * actually back up.
 */
export function LeaseDetailSheet({
  leaseId,
  onOpenChange,
}: {
  leaseId: string | null
  onOpenChange: (open: boolean) => void
}) {
  const { data: lease, isLoading } = useLease(leaseId)
  const id = leaseId ?? ""
  const renewLease = useRenewLease(id)
  const revokeLease = useRevokeLease(id)
  const [confirmingRevoke, setConfirmingRevoke] = useState(false)

  // Real audit events for this exact lease — resource_id on lease.*
  // events is the lease's own ID (confirmed against live data), the same
  // resource_id matching the Audit Explorer's own search already relies
  // on. actorLabel resolves the real requesting identity from data
  // already fetched elsewhere (useUsers/useServiceAccounts) — this is
  // also the only place in this view "who requested this lease" is
  // answerable at all: LeaseResponse itself has no owner/identity field.
  const activity = useAuditLogs({ resource_id: leaseId ?? "", limit: 5 }, { enabled: leaseId !== null })
  // Gated the same way — LeaseDetailSheet is always present in the tree
  // (LeasesPage renders it unconditionally with leaseId=null until a row
  // is clicked), so without this, opening /leases would immediately fire
  // GET /v1/users and GET /v1/service-accounts before any lease is ever
  // opened, just to have actor names ready "in case."
  const users = useUsers({ enabled: leaseId !== null })
  const serviceAccounts = useServiceAccounts({ enabled: leaseId !== null })

  function handleRenew() {
    renewLease.mutate(
      {},
      {
        onSuccess: () => toast.success("Lease renewed."),
        onError: (error) => toast.error(friendlyErrorMessage(error)),
      },
    )
  }

  function handleRevoke() {
    revokeLease.mutate("revoked from the UI", {
      onSuccess: () => {
        toast.success("Lease revoked. The credential is no longer active.")
        setConfirmingRevoke(false)
      },
      onError: (error) => {
        toast.error(friendlyErrorMessage(error))
        setConfirmingRevoke(false)
      },
    })
  }

  const status = lease ? displayStatus(lease) : null
  const isUsable = lease?.status === "active"

  return (
    <Sheet open={leaseId !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-kanz-surface-elevated text-kanz-primary">
              <Zap className="size-4" strokeWidth={1.75} aria-hidden="true" />
            </span>
            <SheetTitle className="min-w-0 truncate">
              {lease ? leaseTypeLabel(lease.lease_type) : "Lease details"}
            </SheetTitle>
          </div>
          <SheetDescription className="flex items-center gap-2 font-mono">
            <span className="truncate">{lease?.resource_path}</span>
          </SheetDescription>
        </SheetHeader>

        {isLoading && (
          <div className="flex flex-col gap-2 px-4">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-6 w-full" />
          </div>
        )}

        {lease && status && (
          <div className="flex flex-col gap-6 overflow-y-auto px-4 pb-6">
            <section className="flex flex-col gap-3">
              <LeaseStatusBadge status={status} />
              <LeaseLifecycle status={status} />
            </section>

            {(status === "active" || status === "expiring") && (
              <section className="flex flex-col gap-2 border-t pt-4">
                <h3 className="text-sm font-medium">Remaining Lifetime</h3>
                <LeaseCountdown lease={lease} />
              </section>
            )}

            <section className="flex flex-col gap-2 border-t pt-4">
              <h3 className="text-sm font-medium">Lease Information</h3>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <Field label="Lease ID">
                  <span className="font-mono text-xs">{lease.lease_id}</span>
                </Field>
                <Field label="Provider">{leaseTypeLabel(lease.lease_type)}</Field>
                <Field label="Resource">
                  <span className="font-mono text-xs">{lease.resource_path}</span>
                </Field>
                <Field label="TTL">{lease.ttl}</Field>
                <Field label="Created">{formatDate(lease.created_at)}</Field>
                <Field label="Expires">{formatDate(lease.expires_at)}</Field>
                <Field label="Renewable">{lease.renewable ? "Yes" : "No"}</Field>
                {lease.revoked_at && <Field label="Revoked">{formatDate(lease.revoked_at)}</Field>}
              </div>
            </section>

            {lease.provider_metadata && Object.keys(lease.provider_metadata).length > 0 && (
              <section className="flex flex-col gap-2 border-t pt-4">
                <h3 className="text-sm font-medium">Provider details</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  {Object.entries(lease.provider_metadata)
                    // Defense in depth only — the backend's own type
                    // contract (dto.LeaseResponse.ProviderMetadata) already
                    // guarantees no provider ever puts credential material
                    // here; this filter can never actually trigger unless
                    // that contract itself were violated, and exists so a
                    // future bug there fails safe in the UI too rather than
                    // rendering whatever came back verbatim.
                    .filter(([key]) => !/password|secret|token/i.test(key))
                    .map(([key, value]) => (
                      <Field key={key} label={key.replace(/_/g, " ")} labelClassName="capitalize">
                        <span className="font-mono text-xs">{String(value)}</span>
                      </Field>
                    ))}
                </div>
              </section>
            )}

            <section className="flex flex-col gap-2 border-t pt-4">
              <h3 className="text-sm font-medium">Credential</h3>
              <div className="flex items-start gap-2 rounded-lg border border-dashed border-border px-3 py-2.5">
                <KeyRound className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                <p className="text-xs text-muted-foreground">
                  This credential was shown once, immediately after creation, and cannot be
                  retrieved again. If it was lost, revoke this lease and request a new one.
                </p>
              </div>
            </section>

            <section className="flex flex-wrap gap-2 border-t pt-4">
              {lease.renewable && isUsable && (
                <Button variant="outline" size="sm" onClick={handleRenew} disabled={renewLease.isPending}>
                  <RotateCw className="size-3.5" aria-hidden="true" />
                  {renewLease.isPending ? "Renewing…" : "Renew"}
                </Button>
              )}
              {isUsable && (
                <Button variant="destructive" size="sm" onClick={() => setConfirmingRevoke(true)}>
                  <ShieldOff className="size-3.5" aria-hidden="true" />
                  Revoke Lease
                </Button>
              )}
            </section>

            <section className="flex flex-col gap-2 border-t pt-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium">Security Activity</h3>
                <Link
                  to="/audit"
                  className="flex items-center gap-1 text-xs font-medium text-kanz-primary transition-colors hover:text-kanz-primary-glow"
                >
                  View in Audit Explorer
                  <ArrowRight className="size-3" aria-hidden="true" />
                </Link>
              </div>

              {activity.isLoading && (
                <div className="flex flex-col gap-1.5">
                  <Skeleton className="h-8 w-full" />
                  <Skeleton className="h-8 w-full" />
                </div>
              )}

              {!activity.isLoading && activity.isError && (
                <p className="text-xs text-muted-foreground">Could not load security activity.</p>
              )}

              {!activity.isLoading && !activity.isError && activity.data?.data.length === 0 && (
                <div className="flex items-center gap-2 rounded-lg border border-dashed border-border px-3 py-4 text-xs text-muted-foreground">
                  <History className="size-4 shrink-0" strokeWidth={1.5} aria-hidden="true" />
                  No recorded activity for this lease yet.
                </div>
              )}

              {!activity.isLoading && !activity.isError && activity.data && activity.data.data.length > 0 && (
                <ul className="flex flex-col gap-1">
                  {activity.data.data.map((event) => (
                    <li key={event.id} className="flex items-center gap-2.5 rounded-lg px-1.5 py-1.5 text-sm">
                      <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-kanz-surface-elevated text-kanz-primary">
                        <Zap className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
                      </span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-mono text-xs">{event.action}</p>
                        <p className="truncate text-[0.65rem] text-muted-foreground">
                          {actorLabel(event, users.data?.data, serviceAccounts.data?.data)}
                        </p>
                      </div>
                      <span className="shrink-0 text-[0.65rem] text-muted-foreground">
                        {formatRelativeTime(event.occurred_at)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </SheetContent>

      <AlertDialog open={confirmingRevoke} onOpenChange={setConfirmingRevoke}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke this lease?</AlertDialogTitle>
            <AlertDialogDescription>
              <span className="mb-1 block font-medium text-foreground">
                {lease && leaseTypeLabel(lease.lease_type)}
              </span>
              <span className="mb-2 block font-mono text-xs">{lease?.resource_path}</span>
              The temporary credential will no longer be valid. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={handleRevoke}
              disabled={revokeLease.isPending}
            >
              {revokeLease.isPending ? "Revoking…" : "Revoke Lease"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  )
}

function Field({
  label,
  labelClassName,
  children,
}: {
  label: string
  labelClassName?: string
  children: ReactNode
}) {
  return (
    <div>
      <div className={cn("text-muted-foreground", labelClassName)}>{label}</div>
      <div>{children}</div>
    </div>
  )
}
