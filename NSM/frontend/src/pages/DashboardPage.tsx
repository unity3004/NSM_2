import { AuthStatusCard } from "@/features/dashboard/AuthStatusCard"
import { SecurityOverviewCard } from "@/features/dashboard/SecurityOverviewCard"
import { SystemStatusCard } from "@/features/dashboard/SystemStatusCard"
import { RecentActivityPlaceholder } from "@/features/dashboard/RecentActivityPlaceholder"

export function DashboardPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Overview of your account and this session.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <AuthStatusCard />
        <SecurityOverviewCard />
        <SystemStatusCard />
      </div>

      <RecentActivityPlaceholder />
    </div>
  )
}
