import { useMutation, useQueryClient } from "@tanstack/react-query"
import { createServiceAccount } from "@/services/serviceAccountsApi"

export function useCreateServiceAccount() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: createServiceAccount,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["service-accounts"] })
    },
  })
}
