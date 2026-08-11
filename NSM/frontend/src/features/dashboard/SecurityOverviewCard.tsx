import type { ReactNode } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { useCurrentUser } from "@/features/users/useCurrentUser"

// REAL API DATA: every field here comes from GET /v1/users/{id} — the
// backend's own UserResponse. mfa_enabled, email_verified_at, last_login_at,
// and status are all real columns this API already returns; nothing on
// this card is invented or estimated.
export function SecurityOverviewCard() {
  const { data: user, isLoading, isError } = useCurrentUser()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Account security</CardTitle>
        <CardDescription>From your real user profile.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        {isLoading && (
          <>
            <Skeleton className="h-5 w-full" />
            <Skeleton className="h-5 w-full" />
            <Skeleton className="h-5 w-full" />
            <Skeleton className="h-5 w-full" />
          </>
        )}
        {isError && (
          <p className="text-muted-foreground">Could not load account details.</p>
        )}
        {user && (
          <>
            <Row label="Multi-factor authentication">
              <Badge variant={user.mfa_enabled ? "default" : "outline"}>
                {user.mfa_enabled ? "Enabled" : "Not enabled"}
              </Badge>
            </Row>
            <Row label="Email verified">
              <Badge variant={user.email_verified_at ? "default" : "outline"}>
                {user.email_verified_at ? "Verified" : "Unverified"}
              </Badge>
            </Row>
            <Row label="Account status">
              <Badge variant="outline" className="capitalize">
                {user.status.replace("_", " ")}
              </Badge>
            </Row>
            <Row label="Last login">
              <span className="text-xs text-foreground">
                {user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "This session"}
              </span>
            </Row>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      {children}
    </div>
  )
}
