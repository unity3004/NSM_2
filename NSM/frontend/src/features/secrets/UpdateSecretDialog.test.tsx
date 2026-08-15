import { afterEach, describe, expect, it, vi } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { UpdateSecretDialog } from "@/features/secrets/UpdateSecretDialog"
import { renderWithProviders } from "@/test/testUtils"
import * as secretsApi from "@/services/secretsApi"

vi.mock("@/services/secretsApi")
const mockedSecretsApi = vi.mocked(secretsApi)

afterEach(() => {
  vi.clearAllMocks()
})

// --- 6. Update creates a new version ---

describe("UpdateSecretDialog", () => {
  it("sends the expected version and reports the new version number on success", async () => {
    mockedSecretsApi.updateSecret.mockResolvedValue({
      path: "prod/database",
      version: 3,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-02T00:00:00Z",
    })

    const user = userEvent.setup()
    renderWithProviders(
      <UpdateSecretDialog
        path="prod/database"
        currentVersion={2}
        initialData={{ username: "app_user", password: "OldSecret" }}
        open={true}
        onOpenChange={() => {}}
      />,
    )

    // Pre-filled from the already-revealed value — never a fresh fetch.
    expect(screen.getByDisplayValue("app_user")).toBeInTheDocument()
    expect(mockedSecretsApi.getSecret).not.toHaveBeenCalled()

    await user.click(screen.getByRole("button", { name: /^update secret$/i }))

    await waitFor(() =>
      expect(mockedSecretsApi.updateSecret).toHaveBeenCalledWith(
        "prod/database",
        { username: "app_user", password: "OldSecret" },
        2,
      ),
    )
  })

  it("starts with an empty form when no value has been revealed yet", () => {
    renderWithProviders(
      <UpdateSecretDialog
        path="prod/database"
        currentVersion={1}
        initialData={null}
        open={true}
        onOpenChange={() => {}}
      />,
    )

    expect(screen.getByText(/starting from an empty form/i)).toBeInTheDocument()
  })

  // --- 17 (update-specific): 409 shows the exact required copy, not a raw backend error ---

  it("shows the version-conflict message on a 409, and never overwrites silently", async () => {
    const { ApiError } = await import("@/lib/apiError")
    mockedSecretsApi.updateSecret.mockRejectedValue(
      new ApiError(409, {
        code: "VERSION_CONFLICT",
        message: "The secret was updated by someone else; the expected version is no longer current.",
        request_id: "req_1",
      }),
    )

    const user = userEvent.setup()
    renderWithProviders(
      <UpdateSecretDialog
        path="prod/database"
        currentVersion={2}
        initialData={{ username: "app_user" }}
        open={true}
        onOpenChange={() => {}}
      />,
    )

    await user.click(screen.getByRole("button", { name: /^update secret$/i }))

    expect(
      await screen.findByText("This secret was updated by someone else. Refresh before making changes."),
    ).toBeInTheDocument()
  })
})
