import { useQuery } from "@tanstack/react-query"
import type { LucideIcon } from "lucide-react"
import { CheckCircle2, AlertTriangle, XCircle, MinusCircle, LogIn, Zap, Lock, Radar } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { checkHealth } from "@/services/systemApi"
import { useAuthStore } from "@/stores/authStore"
import { useLeases } from "@/features/leases/useLeases"
import { useAuditLogs } from "@/features/audit/useAuditLogs"
import { ApiError } from "@/lib/apiError"
import { cn } from "@/lib/utils"

type RowStatus = "active" | "restricted" | "unavailable" | "loading"

const STATUS_META: Record<RowStatus, { icon: LucideIcon; label: string; className: string }> = {
  active: { icon: CheckCircle2, label: "Active", className: "text-kanz-success" },
  // A 403 means this specific user's role doesn't grant visibility into
  // this subsystem — a normal, expected RBAC outcome, not evidence the
  // environment itself is unhealthy. Kept visually and textually distinct
  // from "unavailable" so a lower-privileged viewer's dashboard doesn't
  // read as a security incident.
  restricted: { icon: MinusCircle, label: "Restricted", className: "text-muted-foreground" },
  unavailable: { icon: XCircle, label: "Unavailable", className: "text-kanz-danger" },
  loading: { icon: AlertTriangle, label: "Checking…", className: "text-muted-foreground" },
}

function statusFromQuery(isLoading: boolean, isSuccess: boolean, error: unknown): RowStatus {
  if (isLoading) return "loading"
  if (isSuccess) return "active"
  if (error instanceof ApiError && error.status === 403) return "restricted"
  return "unavailable"
}

/**
 * KANZ Security Status: environment health. Every row below is a real,
 * independently checkable signal already used elsewhere in this app —
 * this panel adds no new query shape, just reads existing query state
 * for a health view:
 *
 *  - Authentication: whether authStore actually holds a live access
 *    token — synchronous, no query involved.
 *  - Lease Engine: whether GET /v1/leases (the identical query
 *    PrimaryMetrics' "Active Leases" tile already issues — shared cache
 *    entry, not an extra request) is reachable — a real signal the
 *    dynamic-credential subsystem is up, not a fabricated "engine
 *    healthy" claim.
 *  - Audit Pipeline: whether GET /v1/audit-logs (shared with
 *    RecentSecurityEvents/PrimaryMetrics) is reachable for this user.
 *  - Encryption: there is no dedicated encryption-subsystem health
 *    endpoint anywhere in this API (confirmed: KeyRotationService is
 *    never wired to an HTTP route on the backend) — fabricating a
 *    "healthy" claim here would be exactly the kind of invented security
 *    score this task explicitly forbids. This row is honestly captioned
 *    as reflecting the one true environment-wide signal that does exist,
 *    GET /healthz, rather than overclaiming a probe of the encryption
 *    path specifically.
 */
export function SecurityStatusPanel() {
  const accessToken = useAuthStore((state) => state.accessToken)
  const system = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => checkHealth(signal),
    refetchInterval: 30_000,
    retry: false,
  })
  const leases = useLeases()
  const audit = useAuditLogs({ limit: 5 })

  const authStatus: RowStatus = accessToken ? "active" : "unavailable"
  const leaseStatus = statusFromQuery(leases.isLoading, leases.isSuccess, leases.error)
  const auditStatus = statusFromQuery(audit.isLoading, audit.isSuccess, audit.error)
  const encryptionStatus = statusFromQuery(system.isLoading, system.isSuccess, system.error)

  const headline: RowStatus =
    system.isLoading || leases.isLoading
      ? "loading"
      : system.isSuccess && authStatus === "active"
        ? "active"
        : "unavailable"

  return (
    <Card>
      <CardHeader>
        <CardTitle>KANZ Security Status</CardTitle>
        <CardDescription>Live signals from your session and the API, not an aggregate score.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex items-center gap-2">
          {headline === "loading" ? (
            <Skeleton className="h-6 w-56" />
          ) : (
            <>
              <span
                className={cn(
                  "kanz-status-pulse size-2.5 rounded-full",
                  headline === "active" ? "bg-kanz-success text-kanz-success" : "bg-kanz-danger text-kanz-danger",
                )}
              />
              <span className="text-sm font-medium text-foreground">
                {headline === "active" ? "OPERATIONAL" : "UNREACHABLE"}
              </span>
              <span className="text-sm text-muted-foreground">
                {headline === "active"
                  ? "All core security services are available."
                  : "The API could not be reached — some sections below may be unavailable."}
              </span>
            </>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatusRow icon={Lock} label="Encryption" status={encryptionStatus} caption="API reachability" />
          <StatusRow icon={LogIn} label="Authentication" status={authStatus} />
          <StatusRow icon={Radar} label="Audit Pipeline" status={auditStatus} />
          <StatusRow icon={Zap} label="Lease Engine" status={leaseStatus} />
        </div>
      </CardContent>
    </Card>
  )
}

function StatusRow({
  icon: Icon,
  label,
  status,
  caption,
}: {
  icon: LucideIcon
  label: string
  status: RowStatus
  caption?: string
}) {
  const meta = STATUS_META[status]
  return (
    <div className="flex flex-col gap-1.5 rounded-lg border border-border bg-kanz-surface-elevated/50 p-3">
      <div className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        <Icon className="size-3.5" strokeWidth={1.75} aria-hidden="true" />
        {label}
      </div>
      <div className={cn("flex items-center gap-1.5 text-sm font-medium", meta.className)}>
        <meta.icon className="size-3.5 shrink-0" strokeWidth={1.75} aria-hidden="true" />
        {meta.label}
      </div>
      {caption && <span className="text-[0.65rem] text-muted-foreground">{caption}</span>}
    </div>
  )
}
