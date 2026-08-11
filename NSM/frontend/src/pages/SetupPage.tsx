import { Navigate } from "react-router-dom"
import { AuthLayout } from "@/layouts/AuthLayout"
import { BootstrapForm } from "@/features/setup/BootstrapForm"
import { usePlatformStatus } from "@/features/setup/usePlatformStatus"
import { RouteLoading } from "@/components/RouteLoading"

/**
 * This page's own gate is advisory UX only: if the platform already shows
 * as initialized, there's no reason to show the form the backend would
 * reject anyway. The backend's row-locked POST /v1/platform/bootstrap
 * transaction is the actual, unconditional enforcement (see
 * service.BootstrapService.Bootstrap) — a client that reached this page
 * by any other means (a stale bookmark, a direct API call, a modified
 * frontend build) still could not create a second administrator; it would
 * just get a real 409 CONFLICT back, exactly like BootstrapForm's own
 * error handling already expects.
 */
export function SetupPage() {
  const { data, isLoading } = usePlatformStatus()

  if (isLoading) return <RouteLoading />
  if (data?.initialized) return <Navigate to="/login" replace />

  return (
    <AuthLayout>
      <BootstrapForm />
    </AuthLayout>
  )
}
