import { RouterProvider } from "react-router-dom"
import { AppProviders } from "@/app/providers"
import { router } from "@/routes/router"
import { useTokenRefreshTimer } from "@/features/auth/useTokenRefreshTimer"
import { SessionBootstrap } from "@/features/auth/SessionBootstrap"

/** A component, not a bare hook call, so it participates in the tree at a
 * point where AppProviders' QueryClientProvider is already available. */
function TokenRefreshMount() {
  useTokenRefreshTimer()
  return null
}

export function App() {
  return (
    <AppProviders>
      <SessionBootstrap />
      <TokenRefreshMount />
      <RouterProvider router={router} />
    </AppProviders>
  )
}
