import { Navigate, Outlet, useLocation } from "react-router-dom"
import { useIsAuthenticated } from "@/stores/authStore"

/**
 * Reads authStore reactively — when refreshSession() ultimately fails
 * (invalid refresh token) it calls store.clear(), and this component
 * redirects on its very next render. No imperative navigate() call is
 * needed from inside the API client, which has no router context anyway.
 */
export function ProtectedRoute() {
  const isAuthenticated = useIsAuthenticated()
  const location = useLocation()

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }
  return <Outlet />
}
