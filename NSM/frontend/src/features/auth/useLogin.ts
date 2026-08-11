import { useMutation } from "@tanstack/react-query"
import { login } from "@/services/authApi"
import { useAuthStore } from "@/stores/authStore"
import type { LoginRequest } from "@/types/auth"

export function useLogin() {
  const setTokens = useAuthStore((state) => state.setTokens)

  return useMutation({
    mutationFn: (credentials: LoginRequest) => login(credentials),
    onSuccess: (tokens) => setTokens(tokens),
  })
}
