import { useQuery } from "@tanstack/react-query"
import { checkHealth } from "@/services/systemApi"
import { useCurrentUser } from "@/features/users/useCurrentUser"
import { cn } from "@/lib/utils"

/** "Good morning/afternoon/evening" from the visitor's own local clock —
 * real, not fabricated; it's simply reading Date() the same way any
 * client-side greeting would. */
function timeOfDayGreeting(): string {
  const hour = new Date().getHours()
  if (hour < 12) return "Good morning"
  if (hour < 18) return "Good afternoon"
  return "Good evening"
}

/**
 * Dashboard header: a small real-identity greeting, "Security Overview"
 * as the actual page heading, and a live system-reachability badge on
 * the right — the identical `["health"]` GET /healthz query
 * SecurityStatusPanel below also runs (same TanStack Query cache entry,
 * not a second request).
 */
export function DashboardHeader() {
  const { data: user } = useCurrentUser()
  const { isSuccess, isLoading } = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => checkHealth(signal),
    refetchInterval: 30_000,
    retry: false,
  })

  const name = user?.username || user?.email?.split("@")[0]

  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <p className="text-sm text-muted-foreground">
          {timeOfDayGreeting()}
          {name ? `, ${name}` : ""}
        </p>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground">Security Overview</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
          Monitor secrets, identities, temporary access, and security activity across your KANZ environment.
        </p>
      </div>

      {!isLoading && (
        <div className="flex shrink-0 items-center gap-1.5 self-start rounded-full border border-border bg-kanz-surface-elevated px-3 py-1.5">
          <span
            className={cn(
              "kanz-status-pulse size-1.5 rounded-full",
              isSuccess ? "bg-kanz-success text-kanz-success" : "bg-kanz-danger text-kanz-danger",
            )}
          />
          <span className="text-xs font-medium tracking-wide text-foreground uppercase">
            System {isSuccess ? "Operational" : "Unreachable"}
          </span>
        </div>
      )}
    </div>
  )
}
