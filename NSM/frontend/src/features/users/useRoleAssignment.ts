import { useMutation, useQueryClient } from "@tanstack/react-query"
import { assignRole, removeRole } from "@/services/usersApi"

export function useAssignRole(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) => assignRole(userId, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users", userId] })
      queryClient.invalidateQueries({ queryKey: ["roles"] })
    },
  })
}

export function useRemoveRole(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) => removeRole(userId, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users", userId] })
      queryClient.invalidateQueries({ queryKey: ["roles"] })
    },
  })
}
