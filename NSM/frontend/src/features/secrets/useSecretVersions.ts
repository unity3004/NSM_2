import { useQuery } from "@tanstack/react-query"
import { listSecretVersions } from "@/services/secretsApi"

/** GET /v1/secrets/{path}?versions=true — real version metadata (created_at,
 * created_by, current), never a value. Unlike useRevealSecret, this is
 * always safe to fetch as soon as the detail view opens (it carries no
 * plaintext), so it runs eagerly rather than behind an explicit
 * enabled: false + refetch() gate. */
export function useSecretVersions(path: string | null) {
  return useQuery({
    queryKey: ["secrets", path, "versions"],
    queryFn: ({ signal }) => listSecretVersions(path as string, signal),
    enabled: path !== null,
  })
}
