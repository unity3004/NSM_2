import { describe, expect, it } from "vitest"
import { displayStatus, remainingFraction, leaseTypeLabel } from "@/features/leases/leaseDisplay"
import type { LeaseStatus } from "@/types/lease"

const NOW = new Date("2026-01-01T12:00:00Z").getTime()

function lease(overrides: {
  status?: LeaseStatus
  expires_at?: string
  created_at?: string
}): { status: LeaseStatus; expires_at: string; created_at: string } {
  return {
    status: overrides.status ?? "active",
    expires_at: overrides.expires_at ?? "2026-01-01T13:00:00Z",
    created_at: overrides.created_at ?? "2026-01-01T11:00:00Z",
  }
}

// --- displayStatus: derived purely from real server status + expires_at ---

describe("displayStatus", () => {
  it("is 'revoked' whenever the server says so, regardless of expiry", () => {
    expect(displayStatus(lease({ status: "revoked", expires_at: "2026-01-01T13:00:00Z" }), NOW)).toBe("revoked")
  })

  it("is 'expired' whenever the server already says so", () => {
    expect(displayStatus(lease({ status: "expired" }), NOW)).toBe("expired")
  })

  it("is 'expired' for a server-reported 'active' lease whose real expiry has already passed", () => {
    // The backend's own sweep runs periodically, not instantaneously — the
    // UI shouldn't wait for it to catch up on an already-past timestamp.
    expect(displayStatus(lease({ status: "active", expires_at: "2026-01-01T11:59:00Z" }), NOW)).toBe("expired")
  })

  it("is 'expiring' for an active lease inside the 5-minute window", () => {
    expect(displayStatus(lease({ status: "active", expires_at: "2026-01-01T12:03:00Z" }), NOW)).toBe("expiring")
  })

  it("is 'active' for an active lease well outside the 5-minute window", () => {
    expect(displayStatus(lease({ status: "active", expires_at: "2026-01-01T13:00:00Z" }), NOW)).toBe("active")
  })
})

// --- remainingFraction: honest re-derivation from real timestamps, including after renewal ---

describe("remainingFraction", () => {
  it("is 1 immediately after creation and 0 once expired", () => {
    expect(
      remainingFraction({ created_at: "2026-01-01T12:00:00Z", expires_at: "2026-01-01T13:00:00Z" }, NOW),
    ).toBeCloseTo(1, 5)
    expect(
      remainingFraction({ created_at: "2026-01-01T11:00:00Z", expires_at: "2026-01-01T12:00:00Z" }, NOW),
    ).toBeCloseTo(0, 5)
  })

  it("is roughly the true midpoint halfway through the lease's real lifetime", () => {
    expect(
      remainingFraction({ created_at: "2026-01-01T11:00:00Z", expires_at: "2026-01-01T13:00:00Z" }, NOW),
    ).toBeCloseTo(0.5, 5)
  })

  it("recomputes a larger total (and so a higher remaining fraction) after a renewal pushes expires_at later, without created_at changing", () => {
    const beforeRenewal = remainingFraction(
      { created_at: "2026-01-01T11:00:00Z", expires_at: "2026-01-01T12:10:00Z" },
      NOW,
    )
    const afterRenewal = remainingFraction(
      { created_at: "2026-01-01T11:00:00Z", expires_at: "2026-01-01T14:00:00Z" },
      NOW,
    )
    expect(afterRenewal).toBeGreaterThan(beforeRenewal)
  })
})

// --- leaseTypeLabel: real, known providers get a friendly name; unknown values pass through ---

describe("leaseTypeLabel", () => {
  it("maps known provider types to their friendly label", () => {
    expect(leaseTypeLabel("postgres")).toBe("PostgreSQL")
    expect(leaseTypeLabel("dev-credential")).toBe("Dev credential")
  })

  it("never hides an unrecognized real type behind a fabricated label", () => {
    expect(leaseTypeLabel("some-future-provider")).toBe("some-future-provider")
  })
})
