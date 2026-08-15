import { useQuery } from "@tanstack/react-query"
import { getSecret } from "@/services/secretsApi"

/**
 * GET /v1/secrets/{path}[?version=N] — on demand only. `enabled: false`
 * means mounting a component that calls this hook never fetches anything
 * by itself; a caller must explicitly invoke the returned `refetch()` (see
 * SecretDetailSheet's "Reveal Secret" button) — there is no code path from
 * "the list opened" or "the detail view opened" to a plaintext value
 * leaving the server.
 *
 * `gcTime: 0` means the moment nothing is observing this query anymore
 * (the component unmounts — closing the detail sheet, navigating away, or
 * ProtectedRoute redirecting to /login on session expiry all do this),
 * TanStack Query evicts the decrypted value from its cache immediately
 * rather than keeping it around for a possible future remount. Combined
 * with never persisting the query cache itself (this app's QueryClient is
 * plain in-memory, no persist plugin — see AppProviders), a revealed
 * secret's plaintext exists only as long as something is actively looking
 * at it.
 *
 * version is passed through unchanged to getSecret — omitted, this
 * requests the current version; a specific number requests exactly that
 * immutable historical version, never a range and never "every version."
 */
export function useRevealSecret(path: string, version: number | undefined) {
  return useQuery({
    queryKey: ["secrets", path, "value", version ?? "current"],
    queryFn: ({ signal }) => getSecret(path, version, signal),
    enabled: false,
    gcTime: 0,
    staleTime: 0,
    retry: false,
  })
}
