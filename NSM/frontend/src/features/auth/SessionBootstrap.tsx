import { useEffect } from "react"
import { useAuthStore } from "@/stores/authStore"

/**
 * Mounted once at the app root (see app/App.tsx), the same pattern as
 * TokenRefreshMount. Runs the one real session check this app can perform
 * on boot — see authStore.restoreSession's doc comment for why that check
 * can never find a prior session in this backend's current, cookie-less
 * token model. It still runs as a genuine post-mount effect (not inline
 * during render) so route guards see a real "initializing" render pass
 * first, never a same-tick skip straight to "unauthenticated."
 */
export function SessionBootstrap(): null {
  const restoreSession = useAuthStore((state) => state.restoreSession)

  useEffect(() => {
    restoreSession()
  }, [restoreSession])

  return null
}
