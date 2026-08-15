import { useQuery } from "@tanstack/react-query"
import { listSecretPolicies } from "@/services/secretPoliciesApi"

export function useSecretPolicies() {
  return useQuery({
    queryKey: ["secret-policies"],
    queryFn: ({ signal }) => listSecretPolicies(signal),
  })
}
