import { useQuery } from "@tanstack/react-query"
import { getServiceAccount, listServiceAccountCredentials } from "@/services/serviceAccountsApi"

export function useServiceAccount(id: string | null) {
  return useQuery({
    queryKey: ["service-accounts", id],
    queryFn: ({ signal }) => getServiceAccount(id as string, signal),
    enabled: id !== null,
  })
}

export function useServiceAccountCredentials(id: string | null) {
  return useQuery({
    queryKey: ["service-accounts", id, "credentials"],
    queryFn: ({ signal }) => listServiceAccountCredentials(id as string, signal),
    enabled: id !== null,
  })
}
