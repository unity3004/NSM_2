import { useMutation, useQueryClient } from "@tanstack/react-query"
import { bootstrapPlatform } from "@/services/platformApi"

export function useBootstrap() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: bootstrapPlatform,
    onSuccess: () => {
      // The one thing this success actually changes app-wide: /login must
      // stop offering "Initialize your security platform" from now on.
      queryClient.invalidateQueries({ queryKey: ["platform-status"] })
    },
  })
}
