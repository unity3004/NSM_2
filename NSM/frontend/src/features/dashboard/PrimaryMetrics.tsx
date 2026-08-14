import { KeyRound, Zap, Users as UsersIcon, Bot } from "lucide-react"
import { MetricCard } from "@/features/dashboard/MetricCard"
import { useSecrets } from "@/features/secrets/useSecrets"
import { useLeases } from "@/features/leases/useLeases"
import { useUsers } from "@/features/users/useUsers"
import { useServiceAccounts } from "@/features/serviceAccounts/useServiceAccounts"

/**
 * The four primary security-resource tiles — Secrets, Active Leases,
 * Identities, Service Accounts. Every count is real, live data from the
 * same endpoints the rest of the app already reads — nothing here is a
 * new query shape or a fabricated number:
 *
 *  - Secrets: GET /v1/secrets (same call the Secrets page itself uses).
 *  - Active Leases: GET /v1/leases, filtered to status "active" — the
 *    same "active leases" definition this app has used everywhere else
 *    it shows a lease count (dashboard, sidebar's live dot).
 *  - Identities: GET /v1/users — human accounts in this organization.
 *    Deliberately not "human + machine" combined (an earlier illustrative
 *    sketch of this card suggested that) — Service Accounts is its own
 *    separate, real count right next to it, so combining them here would
 *    either double-count or require an API this backend doesn't expose;
 *    "Identities" means exactly what GET /v1/users returns.
 *  - Service Accounts: GET /v1/service-accounts, filtered to status
 *    "active" (the same definition the old ResourceOverviewCard used).
 */
export function PrimaryMetrics() {
  const secrets = useSecrets()
  const leases = useLeases()
  const users = useUsers()
  const serviceAccounts = useServiceAccounts()

  const activeLeaseCount = leases.data?.data.filter((l) => l.status === "active").length ?? 0
  const activeServiceAccountCount =
    serviceAccounts.data?.data.filter((sa) => sa.status === "active").length ?? 0

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <MetricCard
        icon={KeyRound}
        label="Secrets"
        description="Protected assets"
        emptyLabel="No secrets yet"
        href="/secrets"
        isLoading={secrets.isLoading}
        isError={secrets.isError}
        value={secrets.data ? secrets.data.data.length : null}
        possiblyTruncated={secrets.data ? secrets.data.data.length === secrets.data.page.limit : false}
      />
      <MetricCard
        icon={Zap}
        label="Active Leases"
        description="Temporary credentials"
        emptyLabel="No active leases"
        href="/leases"
        isLoading={leases.isLoading}
        isError={leases.isError}
        value={leases.data ? activeLeaseCount : null}
        possiblyTruncated={leases.data ? leases.data.data.length === leases.data.page.limit : false}
      />
      <MetricCard
        icon={UsersIcon}
        label="Identities"
        description="Registered users"
        emptyLabel="No users yet"
        href="/users"
        isLoading={users.isLoading}
        isError={users.isError}
        value={users.data ? users.data.data.length : null}
        possiblyTruncated={users.data ? users.data.data.length === users.data.page.limit : false}
      />
      <MetricCard
        icon={Bot}
        label="Service Accounts"
        description="Machine identities"
        emptyLabel="No active service accounts"
        href="/service-accounts"
        isLoading={serviceAccounts.isLoading}
        isError={serviceAccounts.isError}
        value={serviceAccounts.data ? activeServiceAccountCount : null}
        possiblyTruncated={
          serviceAccounts.data ? serviceAccounts.data.data.length === serviceAccounts.data.page.limit : false
        }
      />
    </div>
  )
}
