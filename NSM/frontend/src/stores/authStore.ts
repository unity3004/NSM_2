import { create } from "zustand"
import type { TokenResponse } from "@/types/auth"

/**
 * The one piece of global client state this app has. Deliberately
 * in-memory only — never persisted to localStorage/sessionStorage/a
 * JS-writable cookie, and never wired to Zustand's persist middleware.
 *
 * Why: this backend issues bearer tokens over JSON (no httpOnly cookie
 * support — confirmed by inspecting the OpenAPI security schemes and every
 * handler this sprint), so any persistent storage this app chose would be
 * fully readable by an XSS bug. Keeping both tokens in memory means a hard
 * page reload loses the session and requires real re-login — a deliberate
 * trade-off, not an oversight. See the architecture review's "Token-
 * handling strategy" section.
 */
interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  sessionId: string | null
  /** Epoch ms the current access token expires at, or null if unset. */
  expiresAt: number | null
  setTokens: (tokens: TokenResponse) => void
  clear: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  refreshToken: null,
  sessionId: null,
  expiresAt: null,
  setTokens: (tokens) =>
    set({
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      sessionId: tokens.session_id,
      expiresAt: Date.now() + tokens.expires_in * 1000,
    }),
  clear: () =>
    set({
      accessToken: null,
      refreshToken: null,
      sessionId: null,
      expiresAt: null,
    }),
}))

/** True whenever an access token is present. Does not check expiry — an
 * expired-but-present token still means "was authenticated"; the API
 * client's refresh-on-401 flow (or its failure, which calls clear()) is
 * what actually resolves that ambiguity against the real backend. */
export function useIsAuthenticated(): boolean {
  return useAuthStore((state) => state.accessToken !== null)
}
