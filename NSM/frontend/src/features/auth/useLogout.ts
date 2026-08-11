import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
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
    // The local session is cleared either way (above), so this is purely
    // informational: the backend call that was supposed to revoke the
    // session/refresh-token family server-side may not have gone through
    // (e.g. offline). Silently succeeding client-side would hide that.
    onError: () => {
      toast.error("Logged out locally, but the server may not have received it.")
    },
  })
}
