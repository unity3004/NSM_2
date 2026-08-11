import { useEffect } from "react"
import { useAuthStore } from "@/stores/authStore"
import { refreshSession } from "@/services/httpClient"

// Refresh this long before actual expiry — absorbs clock drift and network
// latency so a proactive refresh always lands before the token could
// actually expire mid-request. The reactive 401 interceptor in
// httpClient.ts is the safety net if this timer is ever missed (e.g. the
// tab was suspended).
const REFRESH_MARGIN_MS = 60_000

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

    const delay = Math.max(0, expiresAt - Date.now() - REFRESH_MARGIN_MS)
    const timer = setTimeout(() => {
      // A failure already clears the auth store inside refreshSession;
      // ProtectedRoute redirects to /login on its next render. Nothing
      // else to do with the rejection here.
      void refreshSession().catch(() => {})
    }, delay)

    return () => clearTimeout(timer)
  }, [expiresAt])
}
