import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { renderHook, waitFor } from "@testing-library/react"
import { QueryClientProvider } from "@tanstack/react-query"
import { usePermission } from "@/features/auth/usePermission"
import { createTestQueryClient, signInAs, signOut } from "@/test/testUtils"
import * as usersApi from "@/services/usersApi"
import type { UserDetailResponse } from "@/types/user"

vi.mock("@/services/usersApi")
const mockedUsersApi = vi.mocked(usersApi)

beforeEach(() => {
  signInAs("user-1")
})

afterEach(() => {
  vi.clearAllMocks()
  signOut()
})

// --- 18. RBAC controls behave correctly ---

describe("usePermission", () => {
  it("is false while the permission list is still loading (fails closed, never briefly true)", () => {
    mockedUsersApi.getUser.mockReturnValue(new Promise(() => {})) // never resolves
    const queryClient = createTestQueryClient()
    const { result } = renderHook(() => usePermission("secrets:create"), {
      wrapper: ({ children }) => <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>,
    })
    expect(result.current).toBe(false)
  })

  it("is true only for a permission the user actually holds", async () => {
    const user: UserDetailResponse = {
      id: "user-1",
      organization_id: "org-1",
      email: "admin@example.test",
      status: "active",
      mfa_enabled: false,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
      roles: [],
      permissions: [{ id: "p1", resource: "secrets", action: "read", name: "secrets:read", description: undefined }],
    }
    mockedUsersApi.getUser.mockResolvedValue(user)
    const queryClient = createTestQueryClient()
    const { result } = renderHook(
      () => ({ read: usePermission("secrets:read"), create: usePermission("secrets:create") }),
      { wrapper: ({ children }) => <QueryClientProvider client={queryClient}>{children}</QueryClientProvider> },
    )

    await waitFor(() => expect(result.current.read).toBe(true))
    expect(result.current.create).toBe(false)
  })
})
