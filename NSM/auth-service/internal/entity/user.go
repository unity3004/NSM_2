package entity

import "time"

// UserStatus mirrors the user_status Postgres enum.
type UserStatus string

const (
	UserStatusActive              UserStatus = "active"
	UserStatusDisabled            UserStatus = "disabled"
	UserStatusLocked              UserStatus = "locked"
	UserStatusPendingVerification UserStatus = "pending_verification"
)

// User is a human principal. PasswordHash is nil for SSO-only accounts —
// see auth-service-database-schema.md §"users" for why that's nullable
// rather than an empty string.
type User struct {
	ID                  string
	OrganizationID      string
	Email               string
	Username            *string
	PasswordHash        *string
	PasswordAlgo        *string
	Status              UserStatus
	MFAEnabled          bool
	EmailVerifiedAt     *time.Time
	FailedLoginAttempts int16
	LockedUntil         *time.Time
	LastLoginAt         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletedAt           *time.Time
}

// IsLocked reports whether the account is currently under a lockout window.
// Kept as a method on the entity (not duplicated in the service layer) so
// "locked" has exactly one definition anywhere in the codebase.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// UserRole is a direct role grant (user_roles). ExpiresAt supports
// time-bound / just-in-time privileged access — nil means a permanent grant.
type UserRole struct {
	UserID     string
	RoleID     string
	AssignedBy *string
	AssignedAt time.Time
	ExpiresAt  *time.Time
}

// IsExpired reports whether a JIT grant's window has closed.
func (ur *UserRole) IsExpired(now time.Time) bool {
	return ur.ExpiresAt != nil && ur.ExpiresAt.Before(now)
}
