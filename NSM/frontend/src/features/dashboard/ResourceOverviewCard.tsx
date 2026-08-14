import type { ReactNode } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useSecrets } from "@/features/secrets/useSecrets"
import { useServiceAccounts } from "@/features/serviceAccounts/useServiceAccounts"
import { useLeases } from "@/features/leases/useLeases"

/**
 * REAL API DATA, from the same GET /v1/secrets, GET /v1/service-accounts,
 * and GET /v1/leases calls SecretsPage/ServiceAccountsPage/LeasesPage
 * already use (useSecrets/useServiceAccounts/useLeases) — no new endpoint,
 * no synthetic count.
 *
 * None of these three list endpoints implements real pagination yet — each
 * hardcodes `has_more: false` regardless of how many rows actually exist
 * beyond its fixed page size (see secret_handler.go/service_account_handler.go/
 * lease_handler.go's own "no real cursor implementation to plug in yet"
 * comments) — so a returned page that happens to be exactly full (length
 * === page.limit) cannot be trusted as a real total; Stat below appends
 * "+" in exactly that case rather than asserting a count that might be
 * wrong. A page shorter than its own limit, by contrast, is always a
 * genuine, complete total — there is nothing left to truncate.
 *
 * A resource this admin cannot list at all (missing permission — e.g.
 * secrets:list — or, for secrets specifically, the Secrets Engine not
 * being configured in this deployment at all, a real 404) renders
 * "Unavailable" rather than "0": those are different facts, and this
 * component must never blur a confirmed-empty result into a
 * couldn't-check one.
 */
export function ResourceOverviewCard() {
  const secrets = useSecrets()
  const serviceAccounts = useServiceAccounts()
  const leases = useLeases()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Resource overview</CardTitle>
        <CardDescription>Live counts from the real API.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        <Row label="Secrets">
          {secrets.isLoading && <Skeleton className="h-5 w-12" />}
          {secrets.isError && <Unavailable />}
          {secrets.data && (
            <Stat
              count={secrets.data.data.length}
              possiblyTruncated={secrets.data.data.length === secrets.data.page.limit}
              emptyLabel="No secrets yet"
            />
          )}
        </Row>
        <Row label="Active service accounts">
          {serviceAccounts.isLoading && <Skeleton className="h-5 w-12" />}
          {serviceAccounts.isError && <Unavailable />}
          {serviceAccounts.data && (
            <Stat
              count={serviceAccounts.data.data.filter((sa) => sa.status === "active").length}
              possiblyTruncated={serviceAccounts.data.data.length === serviceAccounts.data.page.limit}
              emptyLabel="No active service accounts"
            />
          )}
        </Row>
        <Row label="Active leases">
          {leases.isLoading && <Skeleton className="h-5 w-12" />}
          {leases.isError && <Unavailable />}
          {leases.data && (
            <Stat
              count={leases.data.data.filter((l) => l.status === "active").length}
              possiblyTruncated={leases.data.data.length === leases.data.page.limit}
              emptyLabel="No active leases"
            />
          )}
        </Row>
      </CardContent>
    </Card>
  )
}

function Stat({
  count,
  possiblyTruncated,
  emptyLabel,
}: {
  count: number
  /** Whether the underlying page came back exactly full (page length ===
   * page.limit) — the one signal available for "there may be more rows
   * this hardcoded-page-size endpoint didn't return" (see this file's own
   * doc comment above). Computed by the caller against the *raw* page
   * length, not this (possibly status-filtered) count — a full page can
   * hide more matching rows past it even when the visible filtered count
   * looks small. */
  possiblyTruncated: boolean
  emptyLabel: string
}) {
  if (count === 0) {
    return <span className="text-xs text-muted-foreground">{emptyLabel}</span>
  }
  return (
    <span className="font-mono text-sm font-medium text-foreground">
      {count}
      {possiblyTruncated && "+"}
    </span>
  )
}

function Unavailable() {
  return <span className="text-xs text-muted-foreground">Unavailable</span>
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      {children}
    </div>
  )
}
