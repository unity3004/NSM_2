import { httpClient } from "@/services/httpClient"
import type { BootstrapRequest, BootstrapResponse, PlatformStatusResponse } from "@/types/platform"

/**
 * GET /v1/platform/status. Unauthenticated by design — the whole point is
 * answering "can I even log in yet" before any credential exists to send.
 */
export function getPlatformStatus(signal?: AbortSignal): Promise<PlatformStatusResponse> {
  return httpClient.get<PlatformStatusResponse>("/v1/platform/status", { auth: false, signal })
}

/**
 * POST /v1/platform/bootstrap. Unauthenticated by design, the same way
 * login and register are — there is no token to attach for a caller who,
 * by construction, cannot possibly hold one yet. The backend is the sole
 * authority on whether this succeeds; this call is not gated by anything
 * client-side (see SetupPage's own doc comment).
 */
export function bootstrapPlatform(payload: BootstrapRequest): Promise<BootstrapResponse> {
  return httpClient.post<BootstrapResponse>("/v1/platform/bootstrap", payload, { auth: false })
}
