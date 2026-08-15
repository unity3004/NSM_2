// Mirrors auth-service/internal/dto/secret_policy.go exactly — Sprint 4
// Task 2's path-scoped secret authorization policies.

export type PolicyEffect = "allow" | "deny"
/** "rollback" (Path-Based Secret Authorization phase) is deliberately its
 * own action, not implied by "update" — a rule granting update on a path
 * does not, by itself, grant rolling that path back to an old version.
 * See permSecretsRollback/entity.PolicyActionRollback's own doc comments
 * on the backend. */
export type PolicyAction = "read" | "create" | "update" | "delete" | "list" | "rollback"

export interface PolicyRule {
  path_pattern: string
  effect?: PolicyEffect
  actions: PolicyAction[]
}

/** GET/POST/PUT /v1/secret-policies' row shape — metadata only, no rules.
 * See SecretPolicyDetail for the rule-bearing shape GET .../{policyId}
 * returns. */
export interface SecretPolicyResponse {
  id: string
  organization_id?: string | null
  name: string
  description?: string | null
  created_at: string
  updated_at: string
}

/** One secret_policy_rules row, as returned by the backend (never a bare
 * PolicyRule echoed back — this carries the assigned id too). */
export interface SecretPolicyRuleResponse {
  id: string
  path_pattern: string
  effect: PolicyEffect
  actions: PolicyAction[]
}

/** GET /v1/secret-policies/{policyId}'s body — the policy plus its full
 * rule set. */
export interface SecretPolicyDetailResponse extends SecretPolicyResponse {
  rules: SecretPolicyRuleResponse[]
}

/** POST /v1/secret-policies' body. */
export interface SecretPolicyCreateRequest {
  name: string
  description?: string
  rules: PolicyRule[]
}

/** PUT /v1/secret-policies/{policyId}'s body. rules is nil-vs-empty
 * significant on the backend (omitting it leaves existing rules
 * untouched) — this client only ever sends it when the caller actually
 * means to replace the rule set. */
export interface SecretPolicyUpdateRequest {
  name: string
  description?: string
  rules?: PolicyRule[]
}

/** POST /v1/secret-policies/{policyId}/assignments' body. */
export interface SecretPolicyAssignmentRequest {
  role_id: string
}
