package dto

import "regexp"

// emailPattern is a deliberately loose "looks like an email" check — RFC
// 5322 in full is not worth implementing by hand, and the only address that
// actually matters gets validated for real by sending it mail.
var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// LoginRequest matches components.schemas.LoginRequest.
type LoginRequest struct {
	Email             string  `json:"email"`
	Password          string  `json:"password"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
}

// Validate applies the same rules documented in the OpenAPI spec: email is
// required and must look like an email, password just needs to be
// non-empty (complexity is enforced at signup/reset time, not at login —
// see auth-service-api-design.md §5.1).
func (r LoginRequest) Validate() error {
	var errs ValidationErrors
	if r.Email == "" {
		errs.Add("email", "is required")
	} else if len(r.Email) > 255 || !emailPattern.MatchString(r.Email) {
		errs.Add("email", "must be a valid email address")
	}
	if r.Password == "" {
		errs.Add("password", "is required")
	}
	return errs.Err()
}

// RefreshRequest matches components.schemas.RefreshRequest.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (r RefreshRequest) Validate() error {
	var errs ValidationErrors
	if r.RefreshToken == "" {
		errs.Add("refresh_token", "is required")
	}
	return errs.Err()
}

// TokenResponse matches components.schemas.TokenResponse.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	SessionID    string `json:"session_id"`
}

// ServiceTokenResponse matches components.schemas.ServiceTokenResponse —
// no refresh_token or session_id, since machine callers re-exchange their
// API key rather than holding a refresh chain (see the design note on
// POST /service-accounts/{id}/token).
type ServiceTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// SessionResponse matches components.schemas.Session.
type SessionResponse struct {
	ID                string  `json:"id"`
	UserID            string  `json:"user_id"`
	IPAddress         *string `json:"ip_address,omitempty"`
	UserAgent         *string `json:"user_agent,omitempty"`
	DeviceFingerprint *string `json:"device_fingerprint,omitempty"`
	CreatedAt         string  `json:"created_at"`
	LastActiveAt      string  `json:"last_active_at"`
	ExpiresAt         string  `json:"expires_at"`
}
