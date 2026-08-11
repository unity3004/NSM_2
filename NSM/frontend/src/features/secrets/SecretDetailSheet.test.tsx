import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { SecretDetailSheet } from "@/features/secrets/SecretDetailSheet"
import { renderWithProviders, signInAs, signOut } from "@/test/testUtils"
import * as secretsApi from "@/services/secretsApi"
import * as usersApi from "@/services/usersApi"
import type { UserDetailResponse } from "@/types/user"
import type { SecretResponse } from "@/types/secret"

vi.mock("@/services/secretsApi")
vi.mock("@/services/usersApi")

const mockedSecretsApi = vi.mocked(secretsApi)
const mockedUsersApi = vi.mocked(usersApi)

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

function secretList(overrides: Partial<SecretResponse> = {}): { data: SecretResponse[]; page: { next_cursor: null; has_more: boolean; limit: number } } {
  return {
    data: [
      { path: "prod/database", version: 2, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-02T00:00:00Z", ...overrides },
    ],
    page: { next_cursor: null, has_more: false, limit: 20 },
  }
}

beforeEach(() => {
  signInAs("user-1")
})

afterEach(() => {
  vi.clearAllMocks()
  signOut()
})

// --- 3. Unauthorized user cannot reveal secret ---

describe("SecretDetailSheet, no secrets:read", () => {
  it("never shows a Reveal control and never calls getSecret", async () => {
    mockedUsersApi.getUser.mockResolvedValue(userWithPermissions([]))
    mockedSecretsApi.listSecrets.mockResolvedValue(secretList())

    renderWithProviders(<SecretDetailSheet path="prod/database" onOpenChange={() => {}} />)

    await screen.findByText(/current version: 2/i)
    expect(screen.queryByRole("button", { name: /reveal secret/i })).not.toBeInTheDocument()
    expect(screen.getByText(/don't have permission to reveal/i)).toBeInTheDocument()
    expect(mockedSecretsApi.getSecret).not.toHaveBeenCalled()
  })
})

// --- 4. Authorized user can reveal secret ---

describe("SecretDetailSheet, with secrets:read", () => {
  it("reveals the current version's data only after the Reveal button is clicked", async () => {
    mockedUsersApi.getUser.mockResolvedValue(userWithPermissions(["secrets:read"]))
    mockedSecretsApi.listSecrets.mockResolvedValue(secretList())
    mockedSecretsApi.getSecret.mockResolvedValue({
      path: "prod/database",
      version: 2,
      data: { username: "app_user", password: "SuperSecret" },
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-02T00:00:00Z",
    })

    renderWithProviders(<SecretDetailSheet path="prod/database" onOpenChange={() => {}} />)
    await screen.findByText(/current version: 2/i)

    // Opening the sheet must never fetch plaintext by itself.
    expect(mockedSecretsApi.getSecret).not.toHaveBeenCalled()

    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: /reveal secret/i }))

    await waitFor(() => expect(mockedSecretsApi.getSecret).toHaveBeenCalledWith("prod/database", 2, expect.anything()))
    expect(await screen.findByText("username")).toBeInTheDocument()

    // Masked by default — the raw value must not be in the DOM as text
    // until Show is clicked for that field.
    expect(screen.queryByText("SuperSecret")).not.toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: /show password/i }))
    expect(await screen.findByText("SuperSecret")).toBeInTheDocument()
  })

  // --- 7. Historical version can be retrieved if authorized ---

  it("requests a specific historical version, never the current one, when selected", async () => {
    mockedUsersApi.getUser.mockResolvedValue(userWithPermissions(["secrets:read"]))
    mockedSecretsApi.listSecrets.mockResolvedValue(secretList({ version: 2 }))
    mockedSecretsApi.getSecret.mockResolvedValue({
      path: "prod/database",
      version: 1,
      data: { username: "app_user", password: "OriginalSecret" },
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    })

    renderWithProviders(<SecretDetailSheet path="prod/database" onOpenChange={() => {}} />)
    await screen.findByText(/current version: 2/i)

    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Version 1" }))
    await user.click(screen.getByRole("button", { name: /reveal secret/i }))

    await waitFor(() => expect(mockedSecretsApi.getSecret).toHaveBeenCalledWith("prod/database", 1, expect.anything()))
    // Never silently substitutes the current version for the requested one.
    expect(mockedSecretsApi.getSecret).not.toHaveBeenCalledWith("prod/database", 2, expect.anything())
  })
})

// --- 8 & 9. Delete works, and requires explicit confirmation ---

describe("SecretDetailSheet delete", () => {
  it("shows a confirmation dialog and does not call deleteSecret until confirmed", async () => {
    mockedUsersApi.getUser.mockResolvedValue(userWithPermissions(["secrets:delete"]))
    mockedSecretsApi.listSecrets.mockResolvedValue(secretList())

    renderWithProviders(<SecretDetailSheet path="prod/database" onOpenChange={() => {}} />)
    await screen.findByText(/current version: 2/i)

    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: /^delete secret$/i }))

    expect(await screen.findByText('Delete secret "prod/database"?')).toBeInTheDocument()
    expect(mockedSecretsApi.deleteSecret).not.toHaveBeenCalled()

    await user.click(screen.getByRole("button", { name: /cancel/i }))
    expect(mockedSecretsApi.deleteSecret).not.toHaveBeenCalled()
  })

  it("calls deleteSecret only after the destructive action is explicitly confirmed", async () => {
    mockedUsersApi.getUser.mockResolvedValue(userWithPermissions(["secrets:delete"]))
    mockedSecretsApi.listSecrets.mockResolvedValue(secretList())
    mockedSecretsApi.deleteSecret.mockResolvedValue(undefined)

    const onOpenChange = vi.fn()
    renderWithProviders(<SecretDetailSheet path="prod/database" onOpenChange={onOpenChange} />)
    await screen.findByText(/current version: 2/i)

    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: /^delete secret$/i }))
    await screen.findByText('Delete secret "prod/database"?')
    await user.click(screen.getByRole("button", { name: "Delete" }))

    await waitFor(() => expect(mockedSecretsApi.deleteSecret).toHaveBeenCalledWith("prod/database"))
  })

  it("hides the Delete button entirely without secrets:delete", async () => {
    mockedUsersApi.getUser.mockResolvedValue(userWithPermissions([]))
    mockedSecretsApi.listSecrets.mockResolvedValue(secretList())

    renderWithProviders(<SecretDetailSheet path="prod/database" onOpenChange={() => {}} />)
    await screen.findByText(/current version: 2/i)

    expect(screen.queryByRole("button", { name: /delete secret/i })).not.toBeInTheDocument()
  })
})
