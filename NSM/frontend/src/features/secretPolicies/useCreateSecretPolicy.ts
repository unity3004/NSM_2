import { useMutation, useQueryClient } from "@tanstack/react-query"
import { createSecretPolicy } from "@/services/secretPoliciesApi"

export function useCreateSecretPolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: createSecretPolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secret-policies"] })
    },
  })
}
