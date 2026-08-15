import { CircleDot, AlertTriangle, MinusCircle, XCircle, type LucideIcon } from "lucide-react"
import type { LeaseResponse } from "@/types/lease"

/**
 * The exact set of dynamic-credential providers compiled into the backend
 * (leasing.DevCredentialProvider.Type() / leasing/postgres.Provider.Type())
 * — mirrors CreateLeaseDialog's own LEASE_TYPES list exactly, extracted
 * here so the list/detail views can render the same friendly label
 * without duplicating (or silently drifting from) that mapping. There is
 * no discovery endpoint that lists registered providers, so — like
 * CreateLeaseDialog's own copy already says — this is hand-kept in sync
 * with cmd/server/main.go's registrations.
 */
export const LEASE_TYPE_LABELS: Record<string, string> = {
  "dev-credential": "Dev credential",
  postgres: "PostgreSQL",
}

export function leaseTypeLabel(type: string): string {
  return LEASE_TYPE_LABELS[type] ?? type
}

export type DisplayStatus = "active" | "expiring" | "expired" | "revoked"

// A lease "expiring soon" is a UI-only refinement, not a real value the
// backend's LeaseStatus enum has (active/revoked/expired — see
// types/lease.ts) — it's derived honestly from the lease's own real
// expires_at timestamp, the same way the Dashboard's Security Activity
// chart derives "today" from real occurred_at values, never a fabricated
// status the API doesn't back up.
const EXPIRING_SOON_MS = 5 * 60 * 1000

/**
 * The real server-reported status, refined into what the UI shows:
 *  - "expiring": an "active" lease whose real expires_at falls within
 *    the next 5 minutes.
 *  - "expired": either the server already says so, *or* an "active"
 *    lease whose real expires_at has already passed — the backend's own
 *    expiry sweep runs periodically (see server/main.go's "lease expiry
 *    sweep"), not instantaneously, so this display can catch up faster
 *    than the server's `status` field does. Purely a read of
 *    Date.now() vs. a real timestamp — this never writes to server
 *    state or triggers a request.
 */
export function displayStatus(
  lease: Pick<LeaseResponse, "status" | "expires_at">,
  now: number = Date.now(),
): DisplayStatus {
  if (lease.status === "revoked") return "revoked"
  if (lease.status === "expired") return "expired"
  const remaining = new Date(lease.expires_at).getTime() - now
  if (remaining <= 0) return "expired"
  if (remaining <= EXPIRING_SOON_MS) return "expiring"
  return "active"
}

export const STATUS_META: Record<
  DisplayStatus,
  { label: string; icon: LucideIcon; textClassName: string; dotClassName: string }
> = {
  active: { label: "ACTIVE", icon: CircleDot, textClassName: "text-kanz-success", dotClassName: "bg-kanz-success" },
  expiring: {
    label: "EXPIRING SOON",
    icon: AlertTriangle,
    textClassName: "text-kanz-warning",
    dotClassName: "bg-kanz-warning",
  },
  expired: {
    label: "EXPIRED",
    icon: MinusCircle,
    textClassName: "text-muted-foreground",
    dotClassName: "bg-muted-foreground",
  },
  revoked: { label: "REVOKED", icon: XCircle, textClassName: "text-kanz-danger", dotClassName: "bg-kanz-danger" },
}

/** Fraction of the lease's real lifetime (created_at → expires_at) that
 * remains, clamped to [0, 1] — the basis for the remaining-lifetime
 * progress bar. Recomputes correctly after a renewal: renewing only ever
 * moves expires_at later (created_at is immutable), so the *total* span
 * grows and this fraction reflects that, never a fixed/fake TTL. */
export function remainingFraction(
  lease: Pick<LeaseResponse, "created_at" | "expires_at">,
  now: number = Date.now(),
): number {
  const start = new Date(lease.created_at).getTime()
  const end = new Date(lease.expires_at).getTime()
  const total = end - start
  if (total <= 0) return 0
  const remaining = end - now
  return Math.min(1, Math.max(0, remaining / total))
}
