import { afterEach, describe, expect, it, vi } from "vitest"
import { screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router-dom"
import { AuditLogsPage } from "@/pages/AuditLogsPage"
import { renderWithProviders } from "@/test/testUtils"
import * as auditApi from "@/services/auditApi"
import * as usersApi from "@/services/usersApi"
import * as serviceAccountsApi from "@/services/serviceAccountsApi"
import type { AuditLogResponse } from "@/types/audit"

vi.mock("@/services/auditApi")
vi.mock("@/services/usersApi")
vi.mock("@/services/serviceAccountsApi")

const mockedAuditApi = vi.mocked(auditApi)
const mockedUsersApi = vi.mocked(usersApi)
const mockedServiceAccountsApi = vi.mocked(serviceAccountsApi)

const emptyPage = { next_cursor: null, has_more: false, limit: 25 }
const zeroSummary = { total: 0, success: 0, failure: 0, denied: 0 }

function event(overrides: Partial<AuditLogResponse>): AuditLogResponse {
  return {
    id: "event-1",
    actor_type: "user",
    actor_id: null,
    action: "secret.read",
    resource_type: "secret",
    resource_id: "prod/db",
    result: "success",
    request_id: "req_abc12345",
    record_hash: "hash-1",
    occurred_at: "2026-08-15T12:00:00Z",
    ...overrides,
  }
}

function render() {
  return renderWithProviders(
    <MemoryRouter>
      <AuditLogsPage />
    </MemoryRouter>,
  )
}

function mockIdentities() {
  mockedUsersApi.listUsers.mockResolvedValue({ data: [], page: emptyPage })
  mockedServiceAccountsApi.listServiceAccounts.mockResolvedValue({ data: [], page: emptyPage })
}

afterEach(() => {
  vi.clearAllMocks()
})

describe("AuditLogsPage, real data", () => {
  it("renders real event metadata — action, resource, and status — never a fake row", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({
      data: [
        event({
          id: "e1",
          action: "secret.read",
          resource_type: "secret",
          resource_id: "prod/db",
          metadata: { path: "prod/db" },
          result: "success",
        }),
        event({
          id: "e2",
          action: "secret.delete",
          resource_type: "secret",
          resource_id: "prod/api-key",
          metadata: { path: "prod/api-key" },
          result: "denied",
          actor_id: null,
        }),
      ],
      page: emptyPage,
      summary: { total: 2, success: 1, failure: 0, denied: 1 },
    })

    render()

    expect(await screen.findByText("secret.read")).toBeInTheDocument()
    expect(screen.getByText("secret.delete")).toBeInTheDocument()
    expect(screen.getByText(/secret \/ prod\/db/)).toBeInTheDocument()
    expect(screen.getByText("SUCCESS")).toBeInTheDocument()
    expect(screen.getByText("DENIED")).toBeInTheDocument()
  })

  it("shows an honest empty state when there are genuinely no events and no filters applied", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({ data: [], page: emptyPage, summary: zeroSummary })

    render()

    expect(await screen.findByText("No audit events found")).toBeInTheDocument()
  })

  it("shows a professional error state with retry, never a raw backend error", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockRejectedValue(new Error("pq: connection refused"))

    render()

    expect(await screen.findByText("Unable to load audit events")).toBeInTheDocument()
    expect(screen.queryByText(/pq:|connection refused/i)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument()
  })

  it("shows real summary counts computed server-side, not fabricated numbers", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({
      data: [event({ id: "e1" })],
      page: emptyPage,
      summary: { total: 1284, success: 1241, failure: 31, denied: 12 },
    })

    render()

    expect(await screen.findByText("1,284")).toBeInTheDocument()
    expect(screen.getByText("1,241")).toBeInTheDocument()
    expect(screen.getByText("31")).toBeInTheDocument()
    expect(screen.getByText("12")).toBeInTheDocument()
  })

  it("REGRESSION: searching by real resource path 'search-demo/db' sends resource_id to the backend unchanged", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({ data: [], page: emptyPage, summary: zeroSummary })

    const user = userEvent.setup()
    render()
    await screen.findByText("No audit events found")

    await user.type(screen.getByLabelText("Resource ID / path"), "search-demo/db")
    await user.click(screen.getByRole("button", { name: "Apply filters" }))

    expect(await screen.findByText("Resource ID / path: search-demo/db")).toBeInTheDocument()
    const lastCall = mockedAuditApi.listAuditLogs.mock.calls.at(-1)
    expect(lastCall?.[0]).toMatchObject({ resource_id: "search-demo/db" })
  })

  it("REGRESSION: searching by the opaque resource ID still works", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({ data: [], page: emptyPage, summary: zeroSummary })

    const user = userEvent.setup()
    render()
    await screen.findByText("No audit events found")

    await user.type(screen.getByLabelText("Resource ID / path"), "4e1f6a2c-8b3d-4c9e-9f0a-1234567890ab")
    await user.click(screen.getByRole("button", { name: "Apply filters" }))

    const lastCall = mockedAuditApi.listAuditLogs.mock.calls.at(-1)
    expect(lastCall?.[0]).toMatchObject({ resource_id: "4e1f6a2c-8b3d-4c9e-9f0a-1234567890ab" })
  })

  it("shows a no-match state (distinct from the truly-empty state) when filters return nothing", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({ data: [], page: emptyPage, summary: zeroSummary })

    const user = userEvent.setup()
    render()
    await screen.findByText("No audit events found")

    await user.type(screen.getByLabelText("Action"), "nonexistent.action")
    await user.click(screen.getByRole("button", { name: "Apply filters" }))

    expect(await screen.findByText("No matching events")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Clear filters" }))
    expect(await screen.findByText("No audit events found")).toBeInTheDocument()
  })

  it("removing a filter chip clears that filter and refetches", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({ data: [], page: emptyPage, summary: zeroSummary })

    const user = userEvent.setup()
    render()
    await screen.findByText("No audit events found")

    await user.type(screen.getByLabelText("Request ID"), "req_xyz")
    await user.click(screen.getByRole("button", { name: "Apply filters" }))

    await user.click(await screen.findByRole("button", { name: /Request ID: req_xyz/ }))

    expect(screen.queryByText("Request ID: req_xyz")).not.toBeInTheDocument()
    const lastCall = mockedAuditApi.listAuditLogs.mock.calls.at(-1)
    expect(lastCall?.[0].request_id).toBeUndefined()
  })

  it("never renders a secret or credential value anywhere on the page", async () => {
    mockIdentities()
    mockedAuditApi.listAuditLogs.mockResolvedValue({
      data: [
        event({
          id: "e1",
          action: "secret.created",
          metadata: { path: "prod/db", password: "should-never-render", api_key: "sk_live_should_not_render" },
        }),
      ],
      page: emptyPage,
      summary: { total: 1, success: 1, failure: 0, denied: 0 },
    })

    render()
    await screen.findByText("secret.created")

    expect(screen.queryByText(/should-never-render/)).not.toBeInTheDocument()
    expect(screen.queryByText(/sk_live_should_not_render/)).not.toBeInTheDocument()
  })
})
