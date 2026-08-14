import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter, Routes, Route } from "react-router-dom"
import { ProtectedRoute } from "@/routes/ProtectedRoute"
import { SecretDetailSheet } from "@/features/secrets/SecretDetailSheet"
import { renderWithProviders, signInAs, signOut } from "@/test/testUtils"
import { useAuthStore } from "@/stores/authStore"
import * as secretsApi from "@/services/secretsApi"
import * as usersApi from "@/services/usersApi"
import * as auditApi from "@/services/auditApi"
import type { UserDetailResponse } from "@/types/user"

vi.mock("@/services/secretsApi")
vi.mock("@/services/usersApi")
vi.mock("@/services/auditApi")

const mockedSecretsApi = vi.mocked(secretsApi)
const mockedUsersApi = vi.mocked(usersApi)
const mockedAuditApi = vi.mocked(auditApi)

// A deliberately distinctive marker — if this ever shows up somewhere it
// shouldn't (localStorage, sessionStorage, a URL, a console call), that's
// unambiguous, not a coincidental substring match.
const SECRET_MARKER = "THIS_IS_TEST_SECRET_VALUE_zx91qf"

function authorizedUser(): UserDetailResponse {
  return {
    id: "user-1",
    organization_id: "org-1",
    email: "admin@example.test",
    status: "active",
    mfa_enabled: false,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    roles: [],
    permissions: ["secrets:list", "secrets:read"].map((name, i) => ({
      id: `perm-${i}`,
      resource: name.split(":")[0],
      action: name.split(":")[1],
      name,
      description: undefined,
    })),
  }
}

async function revealSecretWithMarker() {
  mockedUsersApi.getUser.mockResolvedValue(authorizedUser())
  mockedSecretsApi.listSecrets.mockResolvedValue({
    data: [{ path: "prod/database", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }],
    page: { next_cursor: null, has_more: false, limit: 20 },
  })
  mockedSecretsApi.getSecret.mockResolvedValue({
    path: "prod/database",
    version: 1,
    data: { password: SECRET_MARKER },
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  })

  renderWithProviders(
    <MemoryRouter>
      <SecretDetailSheet path="prod/database" onOpenChange={() => {}} />
    </MemoryRouter>,
  )
  await screen.findByText(/current version: 1/i)

  const user = userEvent.setup()
  await user.click(screen.getByRole("button", { name: /reveal secret/i }))
  await screen.findByText("password")
  await user.click(screen.getByRole("button", { name: /show password/i }))
  await screen.findByText(SECRET_MARKER)
}

beforeEach(() => {
  signInAs("user-1")
  mockedAuditApi.listAuditLogs.mockResolvedValue({
    data: [],
    page: { next_cursor: null, has_more: false, limit: 5 },
    summary: { total: 0, success: 0, failure: 0, denied: 0 },
  })
})

afterEach(() => {
  vi.clearAllMocks()
  vi.restoreAllMocks()
  signOut()
  // Not window.localStorage.clear()/window.sessionStorage.clear(): this
  // Node/jsdom combination exposes an experimental Node-native
  // `localStorage` global that isn't jsdom's own storage implementation
  // and throws when accessed here. Each assertion below checks that a
  // *call* never happened, not that storage starts empty, so per-test
  // storage state isn't actually load-bearing to clean up between runs.
})

// --- 11 & 12. Secret values never enter localStorage / sessionStorage ---

describe("Secret values never reach browser storage", () => {
  it("never calls localStorage.setItem with the revealed value", async () => {
    // Storage.prototype is shared by both localStorage and sessionStorage
    // (both implement the same Storage interface) — spying on the method
    // itself catches a call through either, which is what actually matters
    // here (not the storage's own final contents, which this Node/jsdom
    // combination's experimental native localStorage global makes
    // unreliable to inspect directly).
    const setItemSpy = vi.spyOn(Storage.prototype, "setItem")
    await revealSecretWithMarker()

    for (const call of setItemSpy.mock.calls) {
      expect(call.join(" ")).not.toContain(SECRET_MARKER)
    }
  })

  it("never calls sessionStorage.setItem with the revealed value", async () => {
    const setItemSpy = vi.spyOn(Storage.prototype, "setItem")
    await revealSecretWithMarker()

    for (const call of setItemSpy.mock.calls) {
      expect(call.join(" ")).not.toContain(SECRET_MARKER)
    }
  })
})

// --- 13. Secret values are not included in the URL ---

describe("Secret values never enter the URL", () => {
  it("never appears in the page URL after revealing", async () => {
    await revealSecretWithMarker()
    expect(window.location.href).not.toContain(SECRET_MARKER)
    expect(window.location.search).not.toContain(SECRET_MARKER)
  })

  it("getSecret is called with only a path and an optional version number, never a value", async () => {
    await revealSecretWithMarker()
    for (const call of mockedSecretsApi.getSecret.mock.calls) {
      const [path, version] = call
      expect(path).not.toContain(SECRET_MARKER)
      expect(typeof version === "number" || version === undefined).toBe(true)
    }
  })
})

// --- 14. Secret values are not logged ---

describe("Secret values are never logged", () => {
  it("never appears in a console.log/warn/error/debug call", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {})
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {})
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {})
    const debugSpy = vi.spyOn(console, "debug").mockImplementation(() => {})

    await revealSecretWithMarker()

    for (const spy of [logSpy, warnSpy, errorSpy, debugSpy]) {
      for (const call of spy.mock.calls) {
        expect(call.map(String).join(" ")).not.toContain(SECRET_MARKER)
      }
    }
  })
})

// --- 15. Session expiry clears sensitive state ---

describe("Session expiry", () => {
  it("unmounts the revealed secret and redirects to login when the session becomes unauthenticated", async () => {
    mockedUsersApi.getUser.mockResolvedValue(authorizedUser())
    mockedSecretsApi.listSecrets.mockResolvedValue({
      data: [{ path: "prod/database", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }],
      page: { next_cursor: null, has_more: false, limit: 20 },
    })
    mockedSecretsApi.getSecret.mockResolvedValue({
      path: "prod/database",
      version: 1,
      data: { password: SECRET_MARKER },
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    })

    function Screen() {
      return (
        <MemoryRouter initialEntries={["/secrets"]}>
          <Routes>
            <Route path="/login" element={<div>Login page</div>} />
            <Route element={<ProtectedRoute />}>
              <Route
                path="/secrets"
                element={<SecretDetailSheet path="prod/database" onOpenChange={() => {}} />}
              />
            </Route>
          </Routes>
        </MemoryRouter>
      )
    }

    const { rerender } = renderWithProviders(<Screen />)
    await screen.findByText(/current version: 1/i)

    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: /reveal secret/i }))
    await screen.findByText("password")
    await user.click(screen.getByRole("button", { name: /show password/i }))
    await screen.findByText(SECRET_MARKER)

    // Simulate the real trigger: refreshSession() failing calls
    // useAuthStore.getState().clear(), which is exactly this.
    useAuthStore.getState().clear()
    rerender(<Screen />)

    await waitFor(() => expect(screen.getByText("Login page")).toBeInTheDocument())
    expect(screen.queryByText(SECRET_MARKER)).not.toBeInTheDocument()
  })
})
