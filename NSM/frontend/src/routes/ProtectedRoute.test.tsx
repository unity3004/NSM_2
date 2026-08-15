import { afterEach, describe, expect, it, vi } from "vitest"
import { render, screen } from "@testing-library/react"
import { MemoryRouter, Routes, Route } from "react-router-dom"
import { ProtectedRoute } from "@/routes/ProtectedRoute"
import { useAuthStore } from "@/stores/authStore"
import { signOut } from "@/test/testUtils"

// SecretsPage itself pulls in React Query, the real API client, etc. —
// this test only cares whether the route guard lets its content render at
// all, not what the page does once it can, so it's stubbed out.
vi.mock("@/pages/SecretsPage", () => ({
  SecretsPage: () => <div>Secrets page content</div>,
}))

afterEach(() => {
  useAuthStore.setState({
    status: "initializing",
    accessToken: null,
    refreshToken: null,
    sessionId: null,
    expiresAt: null,
  })
})

// --- 1. Unauthenticated user cannot access the Secrets page ---

describe("Secrets route, unauthenticated", () => {
  it("never renders Secrets page content and redirects to /login instead", async () => {
    signOut()
    const { SecretsPage } = await import("@/pages/SecretsPage")

    render(
      <MemoryRouter initialEntries={["/secrets"]}>
        <Routes>
          <Route path="/login" element={<div>Login page</div>} />
          <Route element={<ProtectedRoute />}>
            <Route path="/secrets" element={<SecretsPage />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.queryByText("Secrets page content")).not.toBeInTheDocument()
    expect(screen.getByText("Login page")).toBeInTheDocument()
  })
})

describe("Secrets route, authenticated", () => {
  it("renders Secrets page content once authenticated", async () => {
    useAuthStore.setState({
      status: "authenticated",
      accessToken: "fake",
      refreshToken: "fake",
      sessionId: "fake",
      expiresAt: Date.now() + 60_000,
    })
    const { SecretsPage } = await import("@/pages/SecretsPage")

    render(
      <MemoryRouter initialEntries={["/secrets"]}>
        <Routes>
          <Route path="/login" element={<div>Login page</div>} />
          <Route element={<ProtectedRoute />}>
            <Route path="/secrets" element={<SecretsPage />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByText("Secrets page content")).toBeInTheDocument()
    expect(screen.queryByText("Login page")).not.toBeInTheDocument()
  })
})
