import { useQuery } from "@tanstack/react-query"
import { listSecrets } from "@/services/secretsApi"

// REAL API DATA: every row comes straight from GET /v1/secrets
// (secrets:list-gated by the real backend) — metadata only, never a value.
export function useSecrets() {
  return useQuery({
    queryKey: ["secrets"],
    queryFn: ({ signal }) => listSecrets(signal),
  })
}
