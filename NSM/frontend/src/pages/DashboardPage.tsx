import { DashboardHeader } from "@/features/dashboard/DashboardHeader"
import { SecurityStatusPanel } from "@/features/dashboard/SecurityStatusPanel"
import { PrimaryMetrics } from "@/features/dashboard/PrimaryMetrics"
import { SecurityActivityChart } from "@/features/dashboard/SecurityActivityChart"
import { QuickActions } from "@/features/dashboard/QuickActions"
import { SecurityActivityTimeline } from "@/features/dashboard/SecurityActivityTimeline"

/**
 * KANZ Security Overview — the security control-plane view of this
 * environment, not a generic account/analytics dashboard. Every section
 * reads real data from existing endpoints (see each component's own doc
 * comment for exactly which query); several share the same TanStack
 * Query cache entry (["health"], the limit:5 audit-logs query) so this
 * page issues far fewer real requests than its section count suggests.
 *
 * `max-w-[1600px] mx-auto` matches the same convention the login page
 * uses — AppLayout's <main> itself has no width cap (correct for most
 * pages, e.g. wide tables), so this page caps itself rather than
 * stretching edge-to-edge on an ultrawide display.
 */
export function DashboardPage() {
  return (
    <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-6">
      <DashboardHeader />
      <SecurityStatusPanel />
      <PrimaryMetrics />
      <div className="flex flex-col gap-4 lg:flex-row">
        <SecurityActivityChart />
        <QuickActions />
      </div>
      <SecurityActivityTimeline />
    </div>
  )
}
