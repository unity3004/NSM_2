package dto

import (
	"regexp"
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// passwordPattern enforces the same complexity rule documented on
// UserCreate.password in the OpenAPI spec: at least 12 characters, with at
// least one lowercase, one uppercase, one digit, and one symbol.
var passwordPattern = regexp.MustCompile(`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{12,128}$`)

// UserCreateRequest matches components.schemas.UserCreate.
type UserCreateRequest struct {
	Email      string  `json:"email"`
	Username   *string `json:"username,omitempty"`
	Password   *string `json:"password,omitempty"`
	SendInvite bool    `json:"send_invite,omitempty"`
}

func (r UserCreateRequest) Validate() error {
	var errs ValidationErrors
	if r.Email == "" {
		errs.Add("email", "is required")
	} else if len(r.Email) > 255 || !emailPattern.MatchString(r.Email) {
		errs.Add("email", "must be a valid email address")
	}
	if r.Username != nil && len(*r.Username) > 100 {
		errs.Add("username", "must be at most 100 characters")
	}
	// A password is required unless the invite flow will set one, or the
	// account is SSO-only (no password at all — entity.User.PasswordHash
	// stays nil in that case).
	if r.Password != nil && !passwordPattern.MatchString(*r.Password) {
		errs.Add("password", "must be at least 12 characters and include upper, lower, digit, and symbol")
	}
	return errs.Err()
}

// ToEntity builds the (not-yet-persisted) domain object this request
// describes. Hashing the password is deliberately NOT done here — that's
// util.HashPassword's job, called from the service layer — so dto stays
// free of crypto dependencies.
func (r UserCreateRequest) ToEntity(organizationID string) *entity.User {
	status := entity.UserStatusActive
	if r.SendInvite || r.Password == nil {
		status = entity.UserStatusPendingVerification
	}
	return &entity.User{
		OrganizationID: organizationID,
		Email:          r.Email,
		Username:       r.Username,
		Status:         status,
	}
}

// UserUpdateRequest matches components.schemas.UserUpdate. All fields are
// optional; nil means "leave unchanged" — this is why every field here is
// a pointer even though entity.User.Status is not.
type UserUpdateRequest struct {
	Username   *string            `json:"username,omitempty"`
	Status     *entity.UserStatus `json:"status,omitempty"`
	MFAEnabled *bool              `json:"mfa_enabled,omitempty"`
}

func (r UserUpdateRequest) Validate() error {
	var errs ValidationErrors
	if r.Username != nil && len(*r.Username) > 100 {
		errs.Add("username", "must be at most 100 characters")
	}
	if r.Status != nil {
		switch *r.Status {
		case entity.UserStatusActive, entity.UserStatusDisabled, entity.UserStatusLocked, entity.UserStatusPendingVerification:
		default:
			errs.Add("status", "must be one of active, disabled, locked, pending_verification")
		}
	}
	return errs.Err()
}

// UserResponse matches components.schemas.User — notably, it has no
// PasswordHash field at all, not even omitempty: there is no code path in
// this struct's definition that could leak it.
type UserResponse struct {
	ID              string     `json:"id"`
	OrganizationID  string     `json:"organization_id"`
	Email           string     `json:"email"`
	Username        *string    `json:"username,omitempty"`
	Status          string     `json:"status"`
	MFAEnabled      bool       `json:"mfa_enabled"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// UserResponseFromEntity is the one place a User entity becomes API JSON.
func UserResponseFromEntity(u *entity.User) UserResponse {
	return UserResponse{
		ID:              u.ID,
		OrganizationID:  u.OrganizationID,
		Email:           u.Email,
		Username:        u.Username,
		Status:          string(u.Status),
		MFAEnabled:      u.MFAEnabled,
		EmailVerifiedAt: u.EmailVerifiedAt,
		LastLoginAt:     u.LastLoginAt,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
}
