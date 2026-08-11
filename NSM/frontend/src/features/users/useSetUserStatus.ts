import { useMutation, useQueryClient } from "@tanstack/react-query"
import { disableUser, enableUser } from "@/services/usersApi"

// One hook for both directions — they're the same shape (one user ID in,
// invalidate the same two caches) and the real backend already gates both
// through the same users:disable permission (see the migration seeding
// it). Splitting this into useDisableUser/useEnableUser would just be two
// copies of this same logic.
export function useSetUserStatus(action: "disable" | "enable") {
  const queryClient = useQueryClient()
  const mutationFn = action === "disable" ? disableUser : enableUser

  return useMutation({
    mutationFn,
    onSuccess: (_, userId) => {
      queryClient.invalidateQueries({ queryKey: ["users"] })
      queryClient.invalidateQueries({ queryKey: ["users", userId] })
    },
  })
}
