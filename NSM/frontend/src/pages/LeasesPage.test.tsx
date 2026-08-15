import { afterEach, describe, expect, it, vi } from "vitest"
import { screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { MemoryRouter } from "react-router-dom"
import { LeasesPage } from "@/pages/LeasesPage"
import { renderWithProviders } from "@/test/testUtils"
import * as leasesApi from "@/services/leasesApi"
import type { LeaseResponse } from "@/types/lease"

// LeasesPage always embeds <LeaseDetailSheet leaseId={null} .../> in its
// own tree. That component's useUsers()/useServiceAccounts()/
// useAuditLogs() calls (used to resolve a lease's real requesting
// identity for its own Security Activity section) are all gated on
// leaseId !== null, so none of them actually fire while no test below
// opens the sheet — mocked anyway so a future test that does open it
// doesn't silently hit a real, unmocked network call.
vi.mock("@/services/leasesApi")
// Auto-mocked (no .mockResolvedValue setup needed): as long as they stay
// gated shut, calling them would just resolve to undefined rather than
// making a real network call — safe by default, not because any test
// here configures a specific response.
vi.mock("@/services/usersApi")
vi.mock("@/services/serviceAccountsApi")
vi.mock("@/services/auditApi")

const mockedLeasesApi = vi.mocked(leasesApi)

const emptyPage = { next_cursor: null, has_more: false, limit: 50 }

function lease(overrides: Partial<LeaseResponse>): LeaseResponse {
  return {
    lease_id: "lease-1",
    lease_type: "postgres",
    resource_path: "infra/postgres/demo",
    status: "active",
    renewable: true,
    ttl: "10m",
    created_at: "2026-01-01T11:55:00Z",
    expires_at: "2026-01-01T12:05:00Z",
    ...overrides,
  }
}

function render() {
  return renderWithProviders(
    <MemoryRouter>
      <LeasesPage />
    </MemoryRouter>,
  )
}

afterEach(() => {
  vi.clearAllMocks()
})

describe("LeasesPage, real data", () => {
  it("renders real lease metadata — provider label, path, and status — never a fake row", async () => {
    mockedLeasesApi.listLeases.mockResolvedValue({
      data: [
        lease({ lease_id: "lease-1", lease_type: "postgres", resource_path: "infra/postgres/demo", status: "active" }),
        lease({
          lease_id: "lease-2",
          lease_type: "dev-credential",
          resource_path: "dev/local",
          status: "revoked",
          revoked_at: "2026-01-01T12:00:00Z",
        }),
      ],
      page: emptyPage,
    })

    render()

    expect(await screen.findByText("PostgreSQL")).toBeInTheDocument()
    expect(screen.getByText("infra/postgres/demo")).toBeInTheDocument()
    expect(screen.getByText("Dev credential")).toBeInTheDocument()
    expect(screen.getByText("dev/local")).toBeInTheDocument()
    expect(screen.getByText("REVOKED")).toBeInTheDocument()
  })

  it("shows an honest empty state instead of a fake zero when there are genuinely no leases", async () => {
    mockedLeasesApi.listLeases.mockResolvedValue({ data: [], page: emptyPage })

    render()

    expect(await screen.findByText("No active leases")).toBeInTheDocument()
    expect(screen.getByText(/temporary credentials issued by kanz/i)).toBeInTheDocument()
  })

  it("shows a professional error state with retry, never a raw backend error", async () => {
    mockedLeasesApi.listLeases.mockRejectedValue(new Error("connection refused: pq: too many clients"))

    render()

    expect(await screen.findByText("Unable to load leases")).toBeInTheDocument()
    expect(screen.queryByText(/pq:|connection refused/i)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument()
  })

  it("filters to only revoked leases when the Revoked chip is selected, with no extra network call", async () => {
    mockedLeasesApi.listLeases.mockResolvedValue({
      data: [
        lease({ lease_id: "lease-active", status: "active", resource_path: "infra/postgres/demo" }),
        lease({ lease_id: "lease-revoked", status: "revoked", resource_path: "infra/postgres/old" }),
      ],
      page: emptyPage,
    })

    const user = userEvent.setup()
    render()
    await screen.findByText("infra/postgres/demo")

    await user.click(screen.getByRole("button", { name: "Revoked" }))

    expect(screen.queryByText("infra/postgres/demo")).not.toBeInTheDocument()
    expect(screen.getByText("infra/postgres/old")).toBeInTheDocument()
    expect(mockedLeasesApi.listLeases).toHaveBeenCalledTimes(1)
  })

  it("searches already-fetched metadata locally by resource path", async () => {
    mockedLeasesApi.listLeases.mockResolvedValue({
      data: [
        lease({ lease_id: "lease-1", resource_path: "infra/postgres/demo" }),
        lease({ lease_id: "lease-2", resource_path: "infra/redis/cache" }),
      ],
      page: emptyPage,
    })

    const user = userEvent.setup()
    render()
    await screen.findByText("infra/postgres/demo")

    await user.type(screen.getByRole("textbox", { name: /search leases/i }), "redis")

    expect(screen.queryByText("infra/postgres/demo")).not.toBeInTheDocument()
    expect(screen.getByText("infra/redis/cache")).toBeInTheDocument()
    expect(mockedLeasesApi.listLeases).toHaveBeenCalledTimes(1)
  })

  it("shows real summary counts computed from the fetched leases, not fabricated numbers", async () => {
    mockedLeasesApi.listLeases.mockResolvedValue({
      data: [
        lease({ lease_id: "l1", status: "active", expires_at: "2026-06-01T00:00:00Z" }),
        lease({ lease_id: "l2", status: "active", expires_at: "2026-06-01T00:00:00Z" }),
        lease({ lease_id: "l3", status: "revoked" }),
      ],
      page: emptyPage,
    })

    render()

    // Two real active leases, one real revoked lease — the count values
    // themselves (distinct from the "Active"/"Revoked" labels, which
    // legitimately also appear on the filter chips right below the
    // summary tiles).
    expect(await screen.findByText("2")).toBeInTheDocument()
    expect(screen.getByText("1")).toBeInTheDocument()
    expect(screen.getAllByText("0")).toHaveLength(2) // Expiring Soon and Expired, both genuinely zero here.
  })
})
