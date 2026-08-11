/** Shown by ProtectedRoute/PublicRoute while auth status is
 * "initializing" — deliberately blank of any real or placeholder content,
 * so neither the login form nor protected content ever flashes before the
 * session check resolves. */
export function RouteLoading() {
  return (
    <div className="flex min-h-svh items-center justify-center">
      <div
        role="status"
        aria-label="Loading"
        className="size-6 animate-spin rounded-full border-2 border-muted-foreground/30 border-t-foreground"
      />
    </div>
  )
}
