import { Navigate, Outlet } from "react-router-dom"
import { useAuthStore } from "@/stores/authStore"
import { RouteLoading } from "@/components/RouteLoading"

/** Guards /login — an already-authenticated visitor is sent straight to
 * the dashboard instead of seeing the login form again. Also waits out
 * "initializing" (see ProtectedRoute's doc comment) so a visitor who
 * *does* have a live session never sees a flash of the login form first. */
export function PublicRoute() {
  const status = useAuthStore((state) => state.status)

  if (status === "initializing") {
    return <RouteLoading />
  }
  if (status === "authenticated") {
    return <Navigate to="/dashboard" replace />
  }
  return <Outlet />
}
