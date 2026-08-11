import type { ReactElement, ReactNode } from "react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render } from "@testing-library/react"
import { useAuthStore } from "@/stores/authStore"

/** A fresh QueryClient per test — retry disabled so a mocked rejection
 * resolves to an error state immediately instead of AppProviders' real
 * retry policy (up to 2 retries) slowing every error-path test down. */
export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

export function renderWithProviders(ui: ReactElement, { queryClient = createTestQueryClient() } = {}) {
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return { queryClient, ...render(ui, { wrapper: Wrapper }) }
}

/** A JWT-shaped (but not cryptographically real — nothing in this app
 * verifies the signature client-side, see lib/jwt.ts) string carrying a
 * `sub` claim, since useCurrentUser decodes it purely to know which user
 * ID to fetch via the real GET /v1/users/{id} endpoint. Test-only, never
 * a real credential. */
export function fakeAccessToken(sub: string): string {
  const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
  const payload = btoa(JSON.stringify({ sub, iat: Math.floor(Date.now() / 1000) }))
  return `${header}.${payload}.`
}

/** Sets the auth store to "authenticated" with a fake token naming
 * userId — the same store every real component under test reads via
 * useAuthStore/useIsAuthenticated/useCurrentUser. */
export function signInAs(userId: string) {
  useAuthStore.setState({
    status: "authenticated",
    accessToken: fakeAccessToken(userId),
    refreshToken: "fake-refresh-token",
    sessionId: "fake-session-id",
    expiresAt: Date.now() + 15 * 60 * 1000,
  })
}

export function signOut() {
  useAuthStore.setState({
    status: "unauthenticated",
    accessToken: null,
    refreshToken: null,
    sessionId: null,
    expiresAt: null,
  })
}
