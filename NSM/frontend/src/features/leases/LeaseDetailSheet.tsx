import { useState } from "react"
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
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { useLease } from "@/features/leases/useLeases"
import { useRenewLease, useRevokeLease } from "@/features/leases/useLeaseMutations"
import { friendlyErrorMessage } from "@/lib/errorMessage"
import { RotateCw, ShieldOff } from "lucide-react"
import { toast } from "sonner"
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

// Metadata only — GET /v1/leases/{id} never returns credential material,
// and this component has no field it could render even if the response
// somehow carried one (see LeaseResponse's own doc comment). The one time
// a lease's credential is ever shown is CreateLeaseDialog's own creation
// response, never this page.
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
        toast.success("Lease revoked.")
        setConfirmingRevoke(false)
      },
      onError: (error) => {
        toast.error(friendlyErrorMessage(error))
        setConfirmingRevoke(false)
      },
    })
  }

  const isUsable = lease?.status === "active"

  return (
    <Sheet open={leaseId !== null} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-lg">
        <SheetHeader>
          <div className="flex items-center gap-2">
            <SheetTitle className="font-mono text-base">{lease?.lease_id}</SheetTitle>
            {lease && (
              <Badge variant={statusVariant(lease.status)} className="text-xs">
                {lease.status}
              </Badge>
            )}
          </div>
          <SheetDescription>{lease?.resource_path}</SheetDescription>
        </SheetHeader>

        {isLoading && (
          <div className="flex flex-col gap-2 px-4">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-6 w-full" />
          </div>
        )}

        {lease && (
          <div className="flex flex-col gap-6 overflow-y-auto px-4 pb-6">
            <section className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <div className="text-muted-foreground">Type</div>
                <div>{lease.lease_type}</div>
              </div>
              <div>
                <div className="text-muted-foreground">TTL</div>
                <div>{lease.ttl}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Created</div>
                <div>{formatDate(lease.created_at)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Expires</div>
                <div>{formatDate(lease.expires_at)}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Renewable</div>
                <div>{lease.renewable ? "Yes" : "No"}</div>
              </div>
              {lease.revoked_at && (
                <div>
                  <div className="text-muted-foreground">Revoked</div>
                  <div>{formatDate(lease.revoked_at)}</div>
                </div>
              )}
            </section>

            {lease.provider_metadata && Object.keys(lease.provider_metadata).length > 0 && (
              <section className="flex flex-col gap-2">
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
                      <div key={key}>
                        <div className="text-muted-foreground capitalize">{key.replace(/_/g, " ")}</div>
                        <div className="font-mono text-xs">{String(value)}</div>
                      </div>
                    ))}
                </div>
              </section>
            )}

            <section className="flex flex-wrap gap-2">
              {lease.renewable && isUsable && (
                <Button variant="outline" size="sm" onClick={handleRenew} disabled={renewLease.isPending}>
                  <RotateCw />
                  {renewLease.isPending ? "Renewing…" : "Renew"}
                </Button>
              )}
              {isUsable && (
                <Button variant="destructive" size="sm" onClick={() => setConfirmingRevoke(true)}>
                  <ShieldOff />
                  Revoke
                </Button>
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
              The underlying dynamic credential is invalidated immediately and permanently. This
              cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={handleRevoke}
              disabled={revokeLease.isPending}
            >
              {revokeLease.isPending ? "Revoking…" : "Revoke"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Sheet>
  )
}
