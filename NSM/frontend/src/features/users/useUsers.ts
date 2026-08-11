import { useQuery } from "@tanstack/react-query"
import { listUsers } from "@/services/usersApi"

export function useUsers() {
  return useQuery({
    queryKey: ["users"],
    queryFn: ({ signal }) => listUsers(signal),
  })
}
