import { httpClient } from "@/services/httpClient"

/**
 * GET /healthz — unauthenticated, empty 200 body on success (see
 * healthCheck in the backend's router.go). There is no richer status
 * payload to report; "did the request succeed" is the entire signal this
 * endpoint provides today. Resolves to `true` rather than the backend's
 * actual `void` body — TanStack Query v5 treats a query function
 * resolving to `undefined` as an error, not a success with no data.
 */
export async function checkHealth(signal?: AbortSignal): Promise<true> {
  await httpClient.get<void>("/healthz", { auth: false, signal })
  return true
}
