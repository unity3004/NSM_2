import { afterEach, describe, expect, it, vi } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { CreateSecretDialog } from "@/features/secrets/CreateSecretDialog"
import { renderWithProviders } from "@/test/testUtils"
import * as secretsApi from "@/services/secretsApi"

vi.mock("@/services/secretsApi")
const mockedSecretsApi = vi.mocked(secretsApi)

afterEach(() => {
  vi.clearAllMocks()
})

async function openDialogAndFillValidForm(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: /create secret/i }))
  await user.type(screen.getByLabelText(/^path$/i), "prod/database")
  await user.type(screen.getByRole("textbox", { name: /field key/i }), "username")
  await user.type(screen.getByLabelText(/field value/i), "app_user")
}

// --- 5. Authorized user can create secret ---

describe("CreateSecretDialog", () => {
  it("submits path and data, and closes on success", async () => {
    mockedSecretsApi.createSecret.mockResolvedValue({
      path: "prod/database",
      version: 1,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    })

    const user = userEvent.setup()
    renderWithProviders(<CreateSecretDialog />)
    await openDialogAndFillValidForm(user)
    await user.click(screen.getByRole("button", { name: /^create secret$/i }))

    // createSecret is passed directly as useCreateSecret's mutationFn, so
    // TanStack Query itself calls it with a second (mutation context)
    // argument beyond what this component ever constructs — assert only
    // on the first argument, the actual payload this component built.
    await waitFor(() => expect(mockedSecretsApi.createSecret).toHaveBeenCalled())
    expect(mockedSecretsApi.createSecret.mock.calls[0][0]).toEqual({
      path: "prod/database",
      data: { username: "app_user" },
    })
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  })

  it("rejects a path containing a '..' segment before ever calling the API", async () => {
    const user = userEvent.setup()
    renderWithProviders(<CreateSecretDialog />)
    await user.click(screen.getByRole("button", { name: /create secret/i }))
    await user.type(screen.getByLabelText(/^path$/i), "prod/../etc")
    await user.type(screen.getByRole("textbox", { name: /field key/i }), "k")
    await user.type(screen.getByLabelText(/field value/i), "v")
    await user.click(screen.getByRole("button", { name: /^create secret$/i }))

    expect(await screen.findByText(/must not contain "\." or "\.\." segments/i)).toBeInTheDocument()
    expect(mockedSecretsApi.createSecret).not.toHaveBeenCalled()
  })

  it("rejects duplicate keys before calling the API", async () => {
    const user = userEvent.setup()
    renderWithProviders(<CreateSecretDialog />)
    await user.click(screen.getByRole("button", { name: /create secret/i }))
    await user.type(screen.getByLabelText(/^path$/i), "prod/database")
    await user.click(screen.getByRole("button", { name: /add field/i }))

    const keyInputs = screen.getAllByRole("textbox", { name: /field key/i })
    await user.type(keyInputs[0], "username")
    await user.type(keyInputs[1], "username")
    const valueInputs = screen.getAllByLabelText(/field value/i)
    await user.type(valueInputs[0], "a")
    await user.type(valueInputs[1], "b")

    await user.click(screen.getByRole("button", { name: /^create secret$/i }))

    expect(await screen.findAllByText(/duplicate key/i)).not.toHaveLength(0)
    expect(mockedSecretsApi.createSecret).not.toHaveBeenCalled()
  })

  // --- 16. Duplicate submission is prevented ---

  it("does not submit twice when the create button is clicked repeatedly", async () => {
    let resolveCreate: (value: Awaited<ReturnType<typeof secretsApi.createSecret>>) => void
    mockedSecretsApi.createSecret.mockReturnValue(
      new Promise((resolve) => {
        resolveCreate = resolve
      }),
    )

    const user = userEvent.setup()
    renderWithProviders(<CreateSecretDialog />)
    await openDialogAndFillValidForm(user)

    const submitButton = screen.getByRole("button", { name: /^create secret$/i })
    await user.click(submitButton)
    // The button's own label flips to a pending state and becomes
    // disabled — a second click while the first request is still in
    // flight must not fire a second call.
    await screen.findByRole("button", { name: /creating/i })
    await user.click(screen.getByRole("button", { name: /creating/i }))

    expect(mockedSecretsApi.createSecret).toHaveBeenCalledTimes(1)

    resolveCreate!({
      path: "prod/database",
      version: 1,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    })
  })

  // --- 17. API errors display safely ---

  it("shows a safe, friendly message for a duplicate-path 409 — never a raw backend error", async () => {
    const { ApiError } = await import("@/lib/apiError")
    mockedSecretsApi.createSecret.mockRejectedValue(
      new ApiError(409, { code: "CONFLICT", message: "pq: duplicate key value violates unique constraint", request_id: "req_1" }),
    )

    const user = userEvent.setup()
    renderWithProviders(<CreateSecretDialog />)
    await openDialogAndFillValidForm(user)
    await user.click(screen.getByRole("button", { name: /^create secret$/i }))

    expect(await screen.findByText(/already exists at this path/i)).toBeInTheDocument()
    expect(screen.queryByText(/pq:|constraint|violates/i)).not.toBeInTheDocument()
  })
})
