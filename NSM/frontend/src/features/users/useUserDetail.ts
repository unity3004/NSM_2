import { useQuery } from "@tanstack/react-query"
import { getUser } from "@/services/usersApi"

export function useUserDetail(userId: string | undefined) {
  return useQuery({
    queryKey: ["users", userId],
    queryFn: ({ signal }) => getUser(userId!, signal),
    enabled: !!userId,
  })
}
