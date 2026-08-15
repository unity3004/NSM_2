import { useQuery } from "@tanstack/react-query"
import { listRoles } from "@/services/rolesApi"

export function useRoles() {
  return useQuery({
    queryKey: ["roles"],
    queryFn: ({ signal }) => listRoles(signal),
  })
}
