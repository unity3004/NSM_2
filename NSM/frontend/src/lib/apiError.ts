import type { ErrorBody, FieldError } from "@/types/common"

/**
 * The one error shape every API call in this app throws — normalized from
 * the backend's {"error": {...}} envelope (or synthesized for network-level
 * failures) so callers never branch on fetch/Response internals.
 */
export class ApiError extends Error {
  readonly code: string
  readonly status: number
  readonly requestId?: string
  readonly details?: FieldError[]

  constructor(status: number, body: ErrorBody, options?: ErrorOptions) {
    super(body.message, options)
    this.name = "ApiError"
    this.code = body.code
    this.status = status
    this.requestId = body.request_id
    this.details = body.details
  }

  /** True for the backend's own generic "wrong email/password" response. */
  get isInvalidCredentials() {
    return this.code === "INVALID_CREDENTIALS"
  }

  get isAccountLocked() {
    return this.code === "ACCOUNT_LOCKED"
  }

  get isRateLimited() {
    return this.code === "RATE_LIMITED"
  }

  /** True for PUT /v1/secrets/{path}'s own conflict code — the If-Match
   * header named a version that is no longer current (someone else updated
   * this secret first). Distinct from the generic CONFLICT code (e.g.
   * POST /v1/secrets on a duplicate path) so a caller can show "refresh and
   * retry" copy specifically for this one, not a generic conflict message. */
  get isVersionConflict() {
    return this.code === "VERSION_CONFLICT"
  }

  get isUnauthenticated() {
    return this.code === "UNAUTHENTICATED" || this.status === 401
  }
}

/** Synthesized when the network/transport itself fails — no HTTP response
 * to read a real error envelope from at all (offline, DNS, CORS block). */
export function networkApiError(cause: unknown): ApiError {
  return new ApiError(
    0,
    {
      code: "NETWORK_ERROR",
      message: "Could not reach the server. Check your connection and try again.",
      request_id: "",
    },
    { cause },
  )
}
