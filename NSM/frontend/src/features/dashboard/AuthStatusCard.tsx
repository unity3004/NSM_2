import type { ReactNode } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useAuthStore } from "@/stores/authStore"

// REAL API DATA: sessionId and expiresAt both come straight from the
// login/refresh TokenResponse already held in authStore — nothing here is
// invented. Re-renders automatically after a token refresh updates
// expiresAt, which is enough live accuracy without a per-second ticking
// clock (deliberately avoided — see the design direction's "no
// unnecessary animation").
export function AuthStatusCard() {
  const sessionId = useAuthStore((state) => state.sessionId)
  const expiresAt = useAuthStore((state) => state.expiresAt)

  const expiresLabel = expiresAt
    ? new Date(expiresAt).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "—"

  return (
    <Card>
      <CardHeader>
        <CardTitle>Authentication status</CardTitle>
        <CardDescription>Your current session, from the real API response.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        <Row label="Status">
          <Badge variant="outline" className="gap-1.5 border-emerald-400/30 text-emerald-400">
            <span className="size-1.5 rounded-full bg-emerald-400" />
            Active
          </Badge>
        </Row>
        <Row label="Session ID">
          <span className="font-mono text-xs text-foreground">
            {sessionId ? `${sessionId.slice(0, 8)}…` : "—"}
          </span>
        </Row>
        <Row label="Access token expires">
          <span className="font-mono text-xs text-foreground">{expiresLabel}</span>
        </Row>
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
