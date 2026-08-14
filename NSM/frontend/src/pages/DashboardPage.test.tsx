import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import { MemoryRouter } from "react-router-dom"
import { DashboardPage } from "@/pages/DashboardPage"
import { renderWithProviders, signInAs, signOut } from "@/test/testUtils"
import * as secretsApi from "@/services/secretsApi"
import * as serviceAccountsApi from "@/services/serviceAccountsApi"
import * as leasesApi from "@/services/leasesApi"
import * as auditApi from "@/services/auditApi"
import * as usersApi from "@/services/usersApi"
import * as systemApi from "@/services/systemApi"
import type { UserDetailResponse, UserResponse } from "@/types/user"

vi.mock("@/services/secretsApi")
vi.mock("@/services/serviceAccountsApi")
vi.mock("@/services/leasesApi")
vi.mock("@/services/auditApi")
vi.mock("@/services/usersApi")
vi.mock("@/services/systemApi")

const secrets = vi.mocked(secretsApi)
const serviceAccounts = vi.mocked(serviceAccountsApi)
const leases = vi.mocked(leasesApi)
const audit = vi.mocked(auditApi)
const users = vi.mocked(usersApi)
const system = vi.mocked(systemApi)

function currentUser(): UserDetailResponse {
  return {
    id: "user-1",
    organization_id: "org-1",
    email: "admin@example.test",
    username: "admin",
    status: "active",
    mfa_enabled: false,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    roles: [],
    permissions: [],
  }
}

function userList(count: number): UserResponse[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `user-${i}`,
    organization_id: "org-1",
    email: `user-${i}@example.test`,
    username: `user-${i}`,
    status: "active" as const,
    mfa_enabled: false,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  }))
}

const emptyPage = { next_cursor: null, has_more: false, limit: 20 }

beforeEach(() => {
  signInAs("user-1")
  users.getUser.mockResolvedValue(currentUser())
  system.checkHealth.mockResolvedValue(true)
})

afterEach(() => {
  vi.clearAllMocks()
  signOut()
})

// --- Dashboard (KANZ Security Overview) shows real data, never fabricated statistics ---

describe("DashboardPage, real data", () => {
  it("renders real counts from the API for secrets, active leases, identities, and active service accounts", async () => {
    secrets.listSecrets.mockResolvedValue({
      data: [
        { path: "a", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
        { path: "b", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
        { path: "c", version: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      ],
      page: emptyPage,
    })
    serviceAccounts.listServiceAccounts.mockResolvedValue({
      data: [
        {
          id: "sa-1",
          organization_id: "org-1",
          name: "ci-bot",
          status: "active",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
        {
          id: "sa-2",
          organization_id: "org-1",
          name: "disabled-bot",
          status: "disabled",
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      ],
      page: emptyPage,
    })
    leases.listLeases.mockResolvedValue({
      data: [
        {
          lease_id: "lease-1",
          lease_type: "dynamic-credential",
          resource_path: "db/prod",
          status: "active",
          renewable: true,
          ttl: "1h",
          created_at: "2026-01-01T00:00:00Z",
          expires_at: "2026-01-01T01:00:00Z",
        },
        {
          lease_id: "lease-2",
          lease_type: "dynamic-credential",
          resource_path: "db/staging",
          status: "active",
          renewable: true,
          ttl: "1h",
          created_at: "2026-01-01T00:00:00Z",
          expires_at: "2026-01-01T01:00:00Z",
        },
        {
          lease_id: "lease-3",
          lease_type: "dynamic-credential",
          resource_path: "db/old",
          status: "revoked",
          renewable: false,
          ttl: "1h",
          created_at: "2026-01-01T00:00:00Z",
          expires_at: "2026-01-01T01:00:00Z",
        },
      ],
      page: { ...emptyPage, limit: 50 },
    })
    users.listUsers.mockResolvedValue({ data: userList(4), page: emptyPage })
    audit.listAuditLogs.mockResolvedValue({
      data: [
        {
          id: "evt-1",
          actor_type: "user",
          actor_id: "user-1",
          action: "user.login",
          result: "success",
          record_hash: "hash-1",
          occurred_at: new Date().toISOString(),
        },
      ],
      page: { ...emptyPage, limit: 5 },
      summary: { total: 1, success: 1, failure: 0, denied: 0 },
    })

    renderWithProviders(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText("Security Overview")).toBeInTheDocument()
    // Secrets: exact count, no "+" since the page came back short of its limit.
    expect(await screen.findByText("3")).toBeInTheDocument()
    // Active Leases: the two "active" ones counted, the "revoked" one excluded.
    expect(screen.getByText("2")).toBeInTheDocument()
    // Identities: the real count from GET /v1/users.
    expect(screen.getByText("4")).toBeInTheDocument()
    // Service Accounts (only the one "active" one counted) and the
    // Security Activity chart's own "1 event today" both legitimately
    // render a bare "1" — two distinct real numbers that happen to
    // coincide in this fixture, not a single ambiguous match.
    expect(screen.getAllByText("1")).toHaveLength(2)
    expect(screen.getByText("event today")).toBeInTheDocument()
    // Recent Security Activity: the real action string, not a fabricated one.
    expect(screen.getByText("user.login")).toBeInTheDocument()
  })

  it("shows honest empty states instead of fake zeros when there is genuinely no data", async () => {
    secrets.listSecrets.mockResolvedValue({ data: [], page: emptyPage })
    serviceAccounts.listServiceAccounts.mockResolvedValue({ data: [], page: emptyPage })
    leases.listLeases.mockResolvedValue({ data: [], page: { ...emptyPage, limit: 50 } })
    users.listUsers.mockResolvedValue({ data: [], page: emptyPage })
    audit.listAuditLogs.mockResolvedValue({
      data: [],
      page: { ...emptyPage, limit: 5 },
      summary: { total: 0, success: 0, failure: 0, denied: 0 },
    })

    renderWithProviders(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText("No secrets yet")).toBeInTheDocument()
    expect(screen.getByText("No active leases")).toBeInTheDocument()
    expect(screen.getByText("No users yet")).toBeInTheDocument()
    expect(screen.getByText("No active service accounts")).toBeInTheDocument()
    expect(screen.getByText("No recent security events.")).toBeInTheDocument()
    expect(screen.getByText("No security activity recorded today.")).toBeInTheDocument()
  })

  it("marks a count with '+' only when its page came back exactly full, never overclaiming an exact total", async () => {
    secrets.listSecrets.mockResolvedValue({
      data: Array.from({ length: 20 }, (_, i) => ({
        path: `secret-${i}`,
        version: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:00Z",
      })),
      page: emptyPage,
    })
    serviceAccounts.listServiceAccounts.mockResolvedValue({ data: [], page: emptyPage })
    leases.listLeases.mockResolvedValue({ data: [], page: { ...emptyPage, limit: 50 } })
    users.listUsers.mockResolvedValue({ data: [], page: emptyPage })
    audit.listAuditLogs.mockResolvedValue({
      data: [],
      page: { ...emptyPage, limit: 5 },
      summary: { total: 0, success: 0, failure: 0, denied: 0 },
    })

    renderWithProviders(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText("20+")).toBeInTheDocument()
  })

  it("shows 'Unavailable', not a fake zero, when a resource fails to load", async () => {
    secrets.listSecrets.mockRejectedValue(new Error("secrets engine disabled"))
    serviceAccounts.listServiceAccounts.mockResolvedValue({ data: [], page: emptyPage })
    leases.listLeases.mockResolvedValue({ data: [], page: { ...emptyPage, limit: 50 } })
    users.listUsers.mockResolvedValue({ data: [], page: emptyPage })
    audit.listAuditLogs.mockResolvedValue({
      data: [],
      page: { ...emptyPage, limit: 5 },
      summary: { total: 0, success: 0, failure: 0, denied: 0 },
    })

    renderWithProviders(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    )

    expect(await screen.findByText("Unavailable")).toBeInTheDocument()
    expect(screen.queryByText("No secrets yet")).not.toBeInTheDocument()
  })

  it("shows a generic, non-leaking error message when audit access fails, not fabricated events", async () => {
    secrets.listSecrets.mockResolvedValue({ data: [], page: emptyPage })
    serviceAccounts.listServiceAccounts.mockResolvedValue({ data: [], page: emptyPage })
    leases.listLeases.mockResolvedValue({ data: [], page: { ...emptyPage, limit: 50 } })
    users.listUsers.mockResolvedValue({ data: [], page: emptyPage })
    audit.listAuditLogs.mockRejectedValue(new Error("forbidden"))

    renderWithProviders(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    )

    // Both the Security Activity chart and Recent Security Activity list
    // read from GET /v1/audit-logs and fail the same way — neither
    // exposes the raw backend error, and neither invents events instead.
    // waitFor (not findAllByText, which resolves on the *first* match) —
    // the two components settle into their error state independently, so
    // asserting the final count of 2 needs to tolerate one arriving
    // before the other.
    await waitFor(() => {
      expect(screen.getAllByText("Unable to load security activity.")).toHaveLength(2)
    })
  })
})
