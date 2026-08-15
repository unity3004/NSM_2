import { useQuery } from "@tanstack/react-query"
import { getUser } from "@/services/usersApi"
import { useAuthStore } from "@/stores/authStore"
import { decodeJwtPayload } from "@/lib/jwt"

/**
 * This backend has no /me endpoint — the frontend decodes its own access
 * token's `sub` claim (display-only, never a security decision; see
 * lib/jwt.ts) purely to know which ID to fetch via the real
 * GET /v1/users/{id} endpoint. The backend has already verified the
 * token's signature on every request; this decode never influences what
 * the server actually does.
 */
export function useCurrentUser() {
  const accessToken = useAuthStore((state) => state.accessToken)
  const userId = accessToken ? decodeJwtPayload(accessToken)?.sub : undefined

  return useQuery({
    queryKey: ["users", userId],
    queryFn: ({ signal }) => getUser(userId!, signal),
    enabled: !!userId,
  })
}
