import { useQuery } from "@tanstack/react-query"
import { listUsers } from "@/services/usersApi"

export function useUsers(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ["users"],
    queryFn: ({ signal }) => listUsers(signal),
    enabled: options?.enabled,
  })
}
