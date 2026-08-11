import { useQuery } from "@tanstack/react-query"
import { getPlatformStatus } from "@/services/platformApi"

/**
 * Backs the routing decision on both /login and /setup — but is
 * explicitly advisory, never authoritative: this hook only decides what
 * the frontend *shows*. The backend independently and unconditionally
 * enforces the same rule at POST /v1/platform/bootstrap (see
 * service.BootstrapService.Bootstrap's row-locked transaction) — a client
 * that skipped this check entirely, or lied about its result, still could
 * not create a second administrator.
 */
export function usePlatformStatus() {
  return useQuery({
    queryKey: ["platform-status"],
    queryFn: ({ signal }) => getPlatformStatus(signal),
    // Rarely changes (once, ever, in normal operation) but must never be
    // stale in the one case that matters — the moment right after this
    // browser itself completes a bootstrap — so refetch on every mount
    // rather than trusting a cached "uninitialized" from before that.
    staleTime: 0,
  })
}
