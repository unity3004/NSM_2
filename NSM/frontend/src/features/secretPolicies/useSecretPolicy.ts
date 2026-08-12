import { useQuery } from "@tanstack/react-query"
import { getSecretPolicy, listSecretPolicyAssignments } from "@/services/secretPoliciesApi"

/** The policy detail (with rules) plus its current role assignments — the
 * two calls a detail sheet needs, kept as separate queries (not bundled
 * server-side) since assignments change independently of the policy's own
 * rules and each has its own invalidation key. */
export function useSecretPolicy(policyId: string | null) {
  return useQuery({
    queryKey: ["secret-policies", policyId],
    queryFn: ({ signal }) => getSecretPolicy(policyId as string, signal),
    enabled: policyId !== null,
  })
}

export function useSecretPolicyAssignments(policyId: string | null) {
  return useQuery({
    queryKey: ["secret-policies", policyId, "assignments"],
    queryFn: ({ signal }) => listSecretPolicyAssignments(policyId as string, signal),
    enabled: policyId !== null,
  })
}
