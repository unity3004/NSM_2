import { useMutation, useQueryClient } from "@tanstack/react-query"
import { logout } from "@/services/authApi"
import { useAuthStore } from "@/stores/authStore"

export function useLogout() {
  const queryClient = useQueryClient()
  const clear = useAuthStore((state) => state.clear)
  const refreshToken = useAuthStore((state) => state.refreshToken)

  return useMutation({
    mutationFn: () => logout(refreshToken ?? undefined),
    // Clear local state and cached queries regardless of whether the
    // network call itself succeeded — a failed logout request must never
    // leave the UI looking authenticated.
    onSettled: () => {
      clear()
      queryClient.clear()
    },
  })
}
