import { create } from "zustand"
import type { TokenResponse } from "@/types/auth"

/**
 * Three-state model route guards key off of — deliberately not a boolean.
 * "initializing" is the state between app boot and the one real check this
 * app can perform (see restoreSession below); route guards must render
 * neither the login form nor protected content while in it, or a reload
 * could show a one-frame flash of the wrong screen.
 */
export type AuthStatus = "initializing" | "authenticated" | "unauthenticated"

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
 *
 * This also means restoreSession() below can never actually recover a
 * session across a reload — there is no ambient credential (no cookie) and
 * no persisted refresh token for it to present. It still exists as a real,
 * separate boot phase (not just a synchronous default) so route guards have
 * an honest "haven't checked yet" state distinct from "checked, and there's
 * nothing" — the only two states a memory-only client can ever actually be
 * in after a fresh load.
 */
interface AuthState {
  status: AuthStatus
  accessToken: string | null
  refreshToken: string | null
  sessionId: string | null
  /** Epoch ms the current access token expires at, or null if unset. */
  expiresAt: number | null
  setTokens: (tokens: TokenResponse) => void
  clear: () => void
  /** Resolves the initial "initializing" status. Called once from
   * SessionBootstrap at app root — see that file for why this can never
   * find a real prior session, and what would change here if the backend
   * ever added httpOnly-cookie-based sessions. */
  restoreSession: () => void
}

export const useAuthStore = create<AuthState>((set, get) => ({
  status: "initializing",
  accessToken: null,
  refreshToken: null,
  sessionId: null,
  expiresAt: null,
  setTokens: (tokens) =>
    set({
      status: "authenticated",
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      sessionId: tokens.session_id,
      expiresAt: Date.now() + tokens.expires_in * 1000,
    }),
  clear: () =>
    set({
      status: "unauthenticated",
      accessToken: null,
      refreshToken: null,
      sessionId: null,
      expiresAt: null,
    }),
  restoreSession: () => {
    // No token survives a reload (in-memory only, by design — see the doc
    // comment above), so there is never anything to restore in practice.
    // The check still runs for real rather than being skipped, so a
    // future in-tab call (e.g. after a bfcache restore) reflects whatever
    // state actually exists at that moment instead of an assumption made
    // at boot.
    set({ status: get().accessToken !== null ? "authenticated" : "unauthenticated" })
  },
}))

/** True only once the initial session check has resolved to a real,
 * present access token. Does not check expiry — an expired-but-present
 * token still means "was authenticated"; the API client's refresh-on-401
 * flow (or its failure, which calls clear()) is what actually resolves
 * that ambiguity against the real backend. */
export function useIsAuthenticated(): boolean {
  return useAuthStore((state) => state.status === "authenticated")
}
