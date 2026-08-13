// Mirrors auth-service/internal/dto/service_account.go and
// internal/dto/credential.go exactly — Sprint 5 Task 1's machine-identity
// foundation: service accounts (a non-human principal) and the API-key
// credentials that authenticate them.

export type ServiceAccountStatus = "active" | "disabled"

/** GET/POST/PATCH /v1/service-accounts' row shape. */
export interface ServiceAccountResponse {
  id: string
  organization_id: string
  name: string
  description?: string | null
  status: ServiceAccountStatus
  created_by?: string | null
  created_at: string
  updated_at: string
  last_authenticated_at?: string | null
}

export interface RoleGrant {
  role_id: string
  role_name: string
  assigned_by?: string | null
  assigned_at: string
  expires_at?: string | null
}

export interface PermissionSummary {
  id: string
  resource: string
  action: string
  name: string
  description?: string | null
}

/** GET /v1/service-accounts/{id}'s body — metadata plus its current role
 * grants and the permissions those roles confer. */
export interface ServiceAccountDetailResponse extends ServiceAccountResponse {
  roles: RoleGrant[]
  permissions: PermissionSummary[]
}

export interface ServiceAccountCreateRequest {
  name: string
  description?: string
}

/** PATCH /v1/service-accounts/{id}'s body. status is optional — omitting
 * it leaves the service account's active/disabled state untouched; the
 * backend routes a status change through its own disable/enable logic
 * (which also revokes active credentials on disable), never a raw column
 * write. */
export interface ServiceAccountUpdateRequest {
  name: string
  description?: string
  status?: ServiceAccountStatus
}

export type ApiKeyStatus = "active" | "revoked" | "expired"

/** GET/POST /v1/api-keys' row shape — metadata only, never the secret. */
export interface ApiKeyResponse {
  id: string
  organization_id: string
  owner_user_id?: string | null
  owner_service_account_id?: string | null
  name: string
  key_prefix: string
  status: ApiKeyStatus
  last_used_at?: string | null
  expires_at?: string | null
  created_at: string
  revoked_at?: string | null
  revoked_reason?: string | null
}

/** The one response in the whole API that carries a raw secret — shown
 * exactly once, at creation (or rotation) time, never retrievable again. */
export interface ApiKeyCreatedResponse extends ApiKeyResponse {
  secret: string
}

export interface ApiKeyCreateRequest {
  name: string
  owner_service_account_id: string
  expires_at?: string
}
