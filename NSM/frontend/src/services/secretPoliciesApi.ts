import { httpClient } from "@/services/httpClient"
import type {
  SecretPolicyAssignmentRequest,
  SecretPolicyCreateRequest,
  SecretPolicyDetailResponse,
  SecretPolicyResponse,
  SecretPolicyUpdateRequest,
} from "@/types/secretPolicy"

/** GET /v1/secret-policies — metadata only (no rules). Requires
 * secret_policies:read. */
export function listSecretPolicies(signal?: AbortSignal): Promise<{ data: SecretPolicyResponse[] }> {
  return httpClient.get<{ data: SecretPolicyResponse[] }>("/v1/secret-policies", { signal })
}

/** GET /v1/secret-policies/{policyId} — the policy plus its full rule set.
 * Requires secret_policies:read. */
export function getSecretPolicy(policyId: string, signal?: AbortSignal): Promise<SecretPolicyDetailResponse> {
  return httpClient.get<SecretPolicyDetailResponse>(`/v1/secret-policies/${encodeURIComponent(policyId)}`, {
    signal,
  })
}

/** POST /v1/secret-policies. Requires secret_policies:create. */
export function createSecretPolicy(payload: SecretPolicyCreateRequest): Promise<SecretPolicyResponse> {
  return httpClient.post<SecretPolicyResponse>("/v1/secret-policies", payload, { retryOn401: false })
}

/** PUT /v1/secret-policies/{policyId}. Requires secret_policies:update. */
export function updateSecretPolicy(
  policyId: string,
  payload: SecretPolicyUpdateRequest,
): Promise<SecretPolicyResponse> {
  return httpClient.put<SecretPolicyResponse>(
    `/v1/secret-policies/${encodeURIComponent(policyId)}`,
    payload,
    { retryOn401: false },
  )
}

/** DELETE /v1/secret-policies/{policyId} — a hard delete (cascades to the
 * policy's rules and every role assignment). Requires
 * secret_policies:delete. */
export function deleteSecretPolicy(policyId: string): Promise<void> {
  return httpClient.delete<void>(`/v1/secret-policies/${encodeURIComponent(policyId)}`)
}

/** GET /v1/secret-policies/{policyId}/assignments — every role ID this
 * policy is currently assigned to. Requires secret_policies:read. */
export function listSecretPolicyAssignments(policyId: string, signal?: AbortSignal): Promise<{ data: string[] }> {
  return httpClient.get<{ data: string[] }>(
    `/v1/secret-policies/${encodeURIComponent(policyId)}/assignments`,
    { signal },
  )
}

/** POST /v1/secret-policies/{policyId}/assignments. Requires
 * secret_policies:assign. */
export function assignSecretPolicy(policyId: string, roleId: string): Promise<void> {
  return httpClient.post<void>(
    `/v1/secret-policies/${encodeURIComponent(policyId)}/assignments`,
    { role_id: roleId } satisfies SecretPolicyAssignmentRequest,
    { retryOn401: false },
  )
}

/** DELETE /v1/secret-policies/{policyId}/assignments/{roleId}. Requires
 * secret_policies:assign. */
export function unassignSecretPolicy(policyId: string, roleId: string): Promise<void> {
  return httpClient.delete<void>(
    `/v1/secret-policies/${encodeURIComponent(policyId)}/assignments/${encodeURIComponent(roleId)}`,
  )
}
