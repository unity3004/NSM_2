import { useMutation, useQueryClient } from "@tanstack/react-query"
import { deleteSecretPolicy } from "@/services/secretPoliciesApi"

export function useDeleteSecretPolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (policyId: string) => deleteSecretPolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secret-policies"] })
    },
  })
}
