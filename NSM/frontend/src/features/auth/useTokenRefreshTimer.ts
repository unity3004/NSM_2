import { useEffect } from "react"
import { useAuthStore } from "@/stores/authStore"
import { refreshSession } from "@/services/httpClient"

// Refresh this long before actual expiry — absorbs clock drift and network
// latency so a proactive refresh always lands before the token could
// actually expire mid-request. The reactive 401 interceptor in
// httpClient.ts is the safety net if this timer is ever missed (e.g. the
// tab was suspended).
const REFRESH_MARGIN_MS = 60_000

// Floor on the computed delay below. Without it, an access-token TTL
// shorter than REFRESH_MARGIN_MS (the production default is 15 minutes,
// comfortably above the margin, but AUTH_JWT_ACCESS_TOKEN_TTL is an
// operator-set value) drives the delay negative, clamped to 0 by the
// Math.max below — and a delay of exactly 0 means each successful refresh
// immediately reschedules another one, in a tight loop with no gap for
// React to ever unmount this effect. Confirmed for real against a
// deliberately short TTL: an 8s TTL produced hundreds of refresh calls to
// the live backend in a few seconds before this floor was added. This
// isn't just a test artifact — it's a real, self-inflicted denial of
// service against the backend's own refresh-endpoint rate limiter,
// reachable by nothing more than a misconfigured TTL.
const MIN_REFRESH_DELAY_MS = 5_000

/**
 * Mounted once at the app root (see app/App.tsx). Schedules a silent
 * refresh ~60s before the current access token's known expiry, so an
 * active session never surfaces a visible failed-request-then-retry blip.
 * Shares httpClient's single-flight refreshSession — never starts a second,
 * independent refresh alongside a reactive one triggered by a 401.
 */
export function useTokenRefreshTimer(): void {
  const expiresAt = useAuthStore((state) => state.expiresAt)

  useEffect(() => {
    if (expiresAt === null) return

    const delay = Math.max(MIN_REFRESH_DELAY_MS, expiresAt - Date.now() - REFRESH_MARGIN_MS)
    const timer = setTimeout(() => {
      // A failure already clears the auth store inside refreshSession;
      // ProtectedRoute redirects to /login on its next render. Nothing
      // else to do with the rejection here.
      void refreshSession().catch(() => {})
    }, delay)

    return () => clearTimeout(timer)
  }, [expiresAt])
}
