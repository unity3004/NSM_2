import { describe, expect, it } from "vitest"
import { formatRelativeTime } from "@/lib/utils"

describe("formatRelativeTime", () => {
  it("reports very recent timestamps as 'just now'", () => {
    expect(formatRelativeTime(new Date().toISOString())).toBe("just now")
  })

  it("reports minutes in the past", () => {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString()
    expect(formatRelativeTime(fiveMinutesAgo)).toMatch(/5 minutes ago/)
  })

  it("reports hours in the past", () => {
    const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    expect(formatRelativeTime(twoHoursAgo)).toMatch(/2 hours ago/)
  })
})
