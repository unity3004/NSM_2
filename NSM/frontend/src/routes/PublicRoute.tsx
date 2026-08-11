import { Navigate, Outlet } from "react-router-dom"
import { useIsAuthenticated } from "@/stores/authStore"

/** Guards /login — an already-authenticated visitor is sent straight to
 * the dashboard instead of seeing the login form again. */
export function PublicRoute() {
  const isAuthenticated = useIsAuthenticated()

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }
  return <Outlet />
}
