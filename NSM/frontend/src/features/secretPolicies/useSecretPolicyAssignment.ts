import { useMutation, useQueryClient } from "@tanstack/react-query"
import { assignSecretPolicy, unassignSecretPolicy } from "@/services/secretPoliciesApi"

export function useAssignSecretPolicy(policyId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) => assignSecretPolicy(policyId, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secret-policies", policyId, "assignments"] })
    },
  })
}

export function useUnassignSecretPolicy(policyId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) => unassignSecretPolicy(policyId, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secret-policies", policyId, "assignments"] })
    },
  })
}
