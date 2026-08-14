import { useMutation, useQueryClient } from "@tanstack/react-query"
import { rollbackSecret } from "@/services/secretsApi"

/** path is fixed per call site, mirroring useUpdateSecret(path)'s own
 * shape — the varying parts (which version to restore, what the caller
 * believes is current) travel through .mutate(...) instead. */
export function useRollbackSecret(path: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ targetVersion, expectedVersion }: { targetVersion: number; expectedVersion: number }) =>
      rollbackSecret(path, targetVersion, expectedVersion),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["secrets"] })
      // A rollback creates a new current version — the same "any revealed
      // value for this path is now stale" reasoning useUpdateSecret's own
      // onSuccess already documents, applied identically here.
      queryClient.invalidateQueries({ queryKey: ["secrets", path, "value"] })
      queryClient.invalidateQueries({ queryKey: ["secrets", path, "versions"] })
    },
  })
}
