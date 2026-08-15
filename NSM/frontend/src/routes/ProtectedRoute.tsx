import { Navigate, Outlet, useLocation } from "react-router-dom"
import { useAuthStore } from "@/stores/authStore"
import { RouteLoading } from "@/components/RouteLoading"

/**
 * Reads authStore reactively — when refreshSession() ultimately fails
 * (invalid refresh token) it calls store.clear(), and this component
 * redirects on its very next render. No imperative navigate() call is
 * needed from inside the API client, which has no router context anyway.
 *
 * The "initializing" branch matters even though this backend can never
 * actually restore a session (see authStore's doc comment): without it,
 * a visitor with no session would render as `!isAuthenticated` on the
 * very first frame regardless of *why* — indistinguishable from "checked,
 * and there's nothing" — which is the correct outcome here, but would
 * become a real one-frame flash of protected content the moment this
 * backend gains a real restoration path (e.g. httpOnly cookies) that
 * takes more than one tick to resolve.
 */
export function ProtectedRoute() {
  const status = useAuthStore((state) => state.status)
  const location = useLocation()

  if (status === "initializing") {
    return <RouteLoading />
  }
  if (status === "unauthenticated") {
    return <Navigate to="/login" replace state={{ from: location }} />
  }
  return <Outlet />
}
