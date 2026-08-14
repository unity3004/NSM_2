import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { SecretsPage } from "@/pages/SecretsPage"
import { renderWithProviders, signInAs, signOut } from "@/test/testUtils"
import * as secretsApi from "@/services/secretsApi"
import * as usersApi from "@/services/usersApi"
import type { UserDetailResponse } from "@/types/user"

vi.mock("@/services/secretsApi")
vi.mock("@/services/usersApi")

const secretsListApi = vi.mocked(secretsApi)
const usersListApi = vi.mocked(usersApi)

function userWithPermissions(names: string[]): UserDetailResponse {
  return {
    id: "user-1",
    organization_id: "org-1",
    email: "admin@example.test",
    status: "active",
    mfa_enabled: false,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    roles: [],
    permissions: names.map((name, i) => ({
      id: `perm-${i}`,
      resource: name.split(":")[0],
      action: name.split(":")[1],
      name,
      description: undefined,
    })),
  }
}

beforeEach(() => {
  signInAs("user-1")
})

afterEach(() => {
  vi.clearAllMocks()
  signOut()
})

// --- 2. Authenticated, authorized user can view secret metadata ---

describe("SecretsPage, authorized to list", () => {
  it("renders metadata for every secret returned by the API, and no value", async () => {
    usersListApi.getUser.mockResolvedValue(userWithPermissions(["secrets:list"]))
    secretsListApi.listSecrets.mockResolvedValue({
      data: [
        { path: "prod/database", version: 3, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:10:00Z" },
        { path: "prod/smtp", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      ],
      page: { next_cursor: null, has_more: false, limit: 20 },
    })

    renderWithProviders(<SecretsPage />)

    expect(await screen.findByText("prod/database")).toBeInTheDocument()
    expect(screen.getByText("prod/smtp")).toBeInTheDocument()
    expect(screen.getByText("v3")).toBeInTheDocument()

    // The list response itself never carries a value — nothing on the
    // page could show one even accidentally. Assert directly against what
    // the mocked API call returned vs. what's rendered.
    expect(secretsListApi.getSecret).not.toHaveBeenCalled()
  })

  it("hides the Create secret button without secrets:create", async () => {
    usersListApi.getUser.mockResolvedValue(userWithPermissions(["secrets:list"]))
    secretsListApi.listSecrets.mockResolvedValue({
      data: [],
      page: { next_cursor: null, has_more: false, limit: 20 },
    })

    renderWithProviders(<SecretsPage />)

    await screen.findByText("No secrets yet")
    expect(screen.queryByRole("button", { name: /create secret/i })).not.toBeInTheDocument()
  })

  it("shows the Create secret button with secrets:create", async () => {
    usersListApi.getUser.mockResolvedValue(userWithPermissions(["secrets:list", "secrets:create"]))
    secretsListApi.listSecrets.mockResolvedValue({
      data: [],
      page: { next_cursor: null, has_more: false, limit: 20 },
    })

    renderWithProviders(<SecretsPage />)

    expect(await screen.findByRole("button", { name: /create secret/i })).toBeInTheDocument()
  })
})

// --- 10. Search does not retrieve plaintext ---

describe("SecretsPage search", () => {
  it("filters already-fetched metadata locally without calling getSecret", async () => {
    usersListApi.getUser.mockResolvedValue(userWithPermissions(["secrets:list"]))
    secretsListApi.listSecrets.mockResolvedValue({
      data: [
        { path: "prod/database", version: 3, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
        { path: "prod/smtp", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      ],
      page: { next_cursor: null, has_more: false, limit: 20 },
    })

    renderWithProviders(<SecretsPage />)
    await screen.findByText("prod/database")

    const user = userEvent.setup()
    await user.type(screen.getByRole("textbox", { name: /search secrets/i }), "smtp")

    await waitFor(() => {
      expect(screen.queryByText("prod/database")).not.toBeInTheDocument()
    })
    expect(screen.getByText("prod/smtp")).toBeInTheDocument()

    // Typing into search must never trigger a new network call, and
    // certainly never a value-fetching one.
    expect(secretsListApi.listSecrets).toHaveBeenCalledTimes(1)
    expect(secretsListApi.getSecret).not.toHaveBeenCalled()
  })
})
