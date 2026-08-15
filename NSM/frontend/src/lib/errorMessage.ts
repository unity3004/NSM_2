import { ApiError } from "@/lib/apiError"

/**
 * The one place an ApiError becomes copy a user reads. Generic by design —
 * every branch here deliberately discards the backend's own `message`
 * field for anything except the cases where that message is itself already
 * safe, user-facing copy (see writeServiceError in the backend: every
 * message it writes is already meant for a client, never a raw driver/SQL
 * error — but this mapping still never forwards it verbatim, so a future
 * backend message change can't silently start leaking implementation
 * detail through this app).
 *
 * Callers with more context than a bare status/code — LoginForm's
 * anti-enumeration copy for INVALID_CREDENTIALS, for one — should branch
 * on the specific ApiError getters themselves and fall back to this
 * function only for everything else, rather than duplicating a generic
 * "something went wrong" of their own.
 */
export function friendlyErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return "Something went wrong. Please try again."
  }

  switch (error.status) {
    case 400:
      return "Your request could not be processed. Please try again."
    case 401:
      return "Your session has expired. Please sign in again."
    case 403:
      return "You don't have permission to do that."
    case 404:
      return "We couldn't find what you were looking for."
    case 409:
      return "This conflicts with an existing record."
    case 422:
      return "Please check the highlighted fields."
    case 423:
      return "This account is temporarily locked after repeated failed attempts. Try again later."
    case 429:
      return "Too many attempts. Please try again later."
    case 0:
      // networkApiError's sentinel status — no HTTP response was ever
      // received, so no status-based branch above applies.
      return error.message
    default:
      return "Something went wrong. Please try again."
  }
}
