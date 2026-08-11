import { ApiError, networkApiError } from "@/lib/apiError"
import { API_BASE_URL, ORGANIZATION_ID } from "@/lib/config"
import { useAuthStore } from "@/stores/authStore"
import type { ErrorEnvelope } from "@/types/common"
import type { TokenResponse } from "@/types/auth"

export interface RequestOptions {
  method?: "GET" | "POST" | "DELETE" | "PATCH"
  body?: unknown
  signal?: AbortSignal
  /**
   * Attach the current access token. Defaults to true. Set to false for
   * endpoints that are unauthenticated by design (login, register, refresh)
   * — this also opts the call out of the 401-triggers-refresh interceptor
   * below, which must never apply to the refresh call itself.
   */
  auth?: boolean
}

async function rawRequest(path: string, options: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    // The Go API resolves the caller's tenant from this header today (see
    // organizationIDFromRequest in the backend) rather than a subdomain —
    // sent unconditionally since the handlers that don't read it simply
    // ignore it.
    "X-Organization-Id": ORGANIZATION_ID,
  }
  if (options.auth !== false) {
    const token = useAuthStore.getState().accessToken
    if (token) headers.Authorization = `Bearer ${token}`
  }

  try {
    return await fetch(`${API_BASE_URL}${path}`, {
      method: options.method ?? "GET",
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal: options.signal,
    })
  } catch (err) {
    // AbortError is TanStack Query cancelling a stale request — a normal,
    // expected control-flow signal, never a real API error. Let it
    // propagate as-is so React Query recognizes it.
    if (err instanceof DOMException && err.name === "AbortError") throw err
    throw networkApiError(err)
  }
}

async function parseResponse<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T

  const text = await res.text()
  const body = text.length > 0 ? JSON.parse(text) : undefined

  if (!res.ok) {
    const envelope = body as ErrorEnvelope | undefined
    throw new ApiError(
      res.status,
      envelope?.error ?? {
        code: "UNKNOWN_ERROR",
        message: `Request failed with status ${res.status}.`,
        request_id: "",
      },
    )
  }
  return body as T
}

// Concurrent 401s must share exactly one refresh attempt. Verified against
// the real backend this sprint: refresh tokens are single-use and rotate
// on every call — a second, near-simultaneous refresh is indistinguishable
// to the backend from an attacker replaying a stolen token, and its
// fail-safe response is to revoke the *entire session*. Firing one refresh
// call per failed request would force-log-out a legitimate user the
// moment two requests 401 at once (e.g. two tabs, or two queries on one
// page). This module-level promise is the serialization point.
let refreshPromise: Promise<TokenResponse> | null = null

async function refreshAccessToken(): Promise<TokenResponse> {
  const { refreshToken } = useAuthStore.getState()
  if (!refreshToken) {
    throw new ApiError(401, {
      code: "UNAUTHENTICATED",
      message: "No refresh token available.",
      request_id: "",
    })
  }
  const res = await rawRequest("/v1/auth/token/refresh", {
    method: "POST",
    body: { refresh_token: refreshToken },
    auth: false,
  })
  return parseResponse<TokenResponse>(res)
}

function getOrStartRefresh(): Promise<TokenResponse> {
  if (!refreshPromise) {
    refreshPromise = refreshAccessToken().finally(() => {
      refreshPromise = null
    })
  }
  return refreshPromise
}

/**
 * The one function every typed endpoint wrapper in services/ calls through.
 * Never call fetch directly from a component or feature hook — see this
 * file's own role in the architecture: authentication, refresh-on-401,
 * and error normalization all happen exactly once, here.
 */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const res = await rawRequest(path, options)

  const shouldAttemptRefresh = res.status === 401 && options.auth !== false
  if (!shouldAttemptRefresh) {
    return parseResponse<T>(res)
  }

  await refreshSession()

  const retryRes = await rawRequest(path, options)
  return parseResponse<T>(retryRes)
}

/**
 * Refreshes the session and updates the auth store — shared by the 401
 * interceptor above and the proactive pre-expiry timer
 * (features/auth/useTokenRefreshTimer.ts). Both paths call this exact
 * function, never their own independent refresh call, so the single-flight
 * guarantee in getOrStartRefresh actually holds across *every* trigger, not
 * just concurrent 401s.
 */
export async function refreshSession(): Promise<void> {
  try {
    const refreshed = await getOrStartRefresh()
    useAuthStore.getState().setTokens(refreshed)
  } catch (refreshErr) {
    // The refresh token itself is invalid, expired, or was replayed —
    // there is no session left to recover. Clear local state so the UI's
    // ProtectedRoute redirects to /login on its next render.
    useAuthStore.getState().clear()
    throw refreshErr
  }
}

export const httpClient = {
  get: <T>(path: string, options?: Omit<RequestOptions, "method" | "body">) =>
    apiRequest<T>(path, { ...options, method: "GET" }),
  post: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, "method" | "body">) =>
    apiRequest<T>(path, { ...options, method: "POST", body }),
  delete: <T>(path: string, options?: Omit<RequestOptions, "method" | "body">) =>
    apiRequest<T>(path, { ...options, method: "DELETE" }),
}
