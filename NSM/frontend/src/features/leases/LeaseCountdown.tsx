import { useCountdown } from "@/features/leases/useCountdown"
import { displayStatus, remainingFraction } from "@/features/leases/leaseDisplay"
import { formatRelativeTime, cn } from "@/lib/utils"
import type { LeaseResponse } from "@/types/lease"

/**
 * Remaining-lifetime countdown + optional progress bar, shared by the
 * list row and detail view. Ticks from useCountdown (client-side only,
 * built from the lease's own real expires_at) while the lease is
 * genuinely active; revoked/expired leases show a static, real
 * (formatRelativeTime-based) fact instead of a countdown that would
 * mean nothing for them.
 */
export function LeaseCountdown({ lease, showBar = true }: { lease: LeaseResponse; showBar?: boolean }) {
  const status = displayStatus(lease)
  const countdown = useCountdown(lease.expires_at, lease.status === "active")

  if (status === "revoked") {
    return (
      <span className="text-xs text-muted-foreground">
        Revoked {lease.revoked_at ? formatRelativeTime(lease.revoked_at) : ""}
      </span>
    )
  }

  if (status === "expired") {
    return <span className="text-xs text-muted-foreground">Expired {formatRelativeTime(lease.expires_at)}</span>
  }

  const fraction = remainingFraction(lease)

  return (
    <div className="flex flex-col gap-1">
      <span className={cn("text-xs font-medium", status === "expiring" ? "text-kanz-warning" : "text-muted-foreground")}>
        {countdown.label}
      </span>
      {showBar && (
        <div className="h-1 w-full overflow-hidden rounded-full bg-kanz-surface-elevated" aria-hidden="true">
          <div
            className={cn(
              "h-full rounded-full transition-[width] duration-1000 ease-linear",
              status === "expiring" ? "bg-kanz-warning" : "bg-kanz-primary",
            )}
            style={{ width: `${fraction * 100}%` }}
          />
        </div>
      )}
    </div>
  )
}
