// Mirrors auth-service/internal/dto/user.go's UserResponse exactly —
// notably, there is no password/password_hash field to even omit; the Go
// struct never declares one.

import type { PermissionResponse, RoleGrantResponse } from "@/types/rbac"

export type UserStatus = "active" | "disabled" | "locked" | "pending_verification"

export interface UserResponse {
  id: string
  organization_id: string
  email: string
  username?: string
  status: UserStatus
  mfa_enabled: boolean
  email_verified_at?: string
  last_login_at?: string
  created_at: string
  updated_at: string
}

/** GET /v1/users/{userId}'s body — UserResponse plus resolved role grants
 * and effective permissions. See dto.UserDetailResponse's own doc comment
 * for why neither is ever cached client-side beyond a normal query's
 * staleTime. */
export interface UserDetailResponse extends UserResponse {
  roles: RoleGrantResponse[]
  permissions: PermissionResponse[]
}

/** POST /v1/users — the admin/invite creation path. Mirrors
 * dto.UserCreateRequest. */
export interface UserCreateRequest {
  email: string
  username?: string
  password?: string
  send_invite?: boolean
}
