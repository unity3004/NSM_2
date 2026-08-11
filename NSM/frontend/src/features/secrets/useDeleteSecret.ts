import { useMutation, useQueryClient } from "@tanstack/react-query"
import { deleteSecret } from "@/services/secretsApi"

export function useDeleteSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (path: string) => deleteSecret(path),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] })
    },
  })
}
