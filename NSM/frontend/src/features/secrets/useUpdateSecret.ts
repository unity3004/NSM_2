import { useMutation, useQueryClient } from "@tanstack/react-query"
import { updateSecret } from "@/services/secretsApi"

/** path is fixed per call site (the secret currently open in
 * SecretDetailSheet) — mirrors useAssignRole(userId)'s shape (the fixed
 * part lives in the hook call, the varying part in .mutate(...)). */
export function useUpdateSecret(path: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ data, expectedVersion }: { data: Record<string, string>; expectedVersion: number }) =>
      updateSecret(path, data, expectedVersion),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] })
      // A revealed value (any version) for this path is now stale the
      // moment a new version exists — drop it rather than risk a stale
      // plaintext value being shown as if it were current. gcTime: 0 on
      // useRevealSecret already means an inactive one disappears on its
      // own, but this secret's detail view is still open and mounted right
      // now (this mutation ran from inside it), so its reveal query is
      // still active — an explicit invalidate is what actually clears it
      // here, not gcTime.
      queryClient.invalidateQueries({ queryKey: ["secrets", path, "value"] })
    },
  })
}
