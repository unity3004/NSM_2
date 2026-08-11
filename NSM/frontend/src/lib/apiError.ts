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
