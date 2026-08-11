// Mirrors auth-service/internal/dto/user.go's UserResponse exactly —
// notably, there is no password/password_hash field to even omit; the Go
// struct never declares one.

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
