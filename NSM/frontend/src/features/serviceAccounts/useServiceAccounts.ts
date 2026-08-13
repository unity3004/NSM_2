import { useQuery } from "@tanstack/react-query"
import { listServiceAccounts } from "@/services/serviceAccountsApi"

export function useServiceAccounts() {
  return useQuery({
    queryKey: ["service-accounts"],
    queryFn: ({ signal }) => listServiceAccounts(signal),
  })
}
