// Mirrors auth-service/internal/dto/rbac.go exactly.

export interface PermissionResponse {
  id: string
  resource: string
  action: string
  name: string
  description?: string
}

export interface RoleResponse {
  id: string
  organization_id?: string
  name: string
  description?: string
  is_system_role: boolean
  created_at: string
  updated_at: string
}

/** GET /v1/roles and GET /v1/roles/{roleId}'s body. */
export interface RoleWithPermissionsResponse extends RoleResponse {
  user_count: number
  permissions: PermissionResponse[]
}

export interface RoleGrantResponse {
  role_id: string
  role_name: string
  assigned_by?: string
  assigned_at: string
  expires_at?: string
}

export interface RoleGrantCreateRequest {
  role_id: string
  expires_at?: string
}
