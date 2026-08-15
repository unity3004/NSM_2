package dto

import "time"

// PlatformStatusResponse is GET /v1/platform/status's body — deliberately
// the only field it has. It must never reveal whether an administrator
// account exists by name, how many users the platform has, or anything
// about its configuration; "should the frontend show setup or login" is
// the entire question this endpoint answers.
type PlatformStatusResponse struct {
	Initialized bool `json:"initialized"`
}

// BootstrapRequest matches components.schemas.PlatformBootstrap — the
// same three fields RegisterRequest accepts (self-service signup), not a
// coincidence: creating the first administrator and creating any other
// user both end up as one entity.User row, so the input shape that
// describes "a new person, with a password" is identical. There is
// deliberately no confirm_password field: password confirmation is a
// client-side typo check (see the frontend's setup form), not something
// the backend needs a second copy of the same secret to verify.
type BootstrapRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Validate applies the identical rules RegisterRequest.Validate already
// enforces — this account is subject to the platform's normal password
// policy, not a weaker one, precisely because it is the most privileged
// account the platform will ever have.
func (r BootstrapRequest) Validate() error {
	var errs ValidationErrors

	if r.Username == "" {
		errs.Add("username", "is required")
	} else if !usernamePattern.MatchString(r.Username) {
		errs.Add("username", "must be 3-100 characters and contain only letters, digits, '.', '_', or '-'")
	}

	if r.Email == "" {
		errs.Add("email", "is required")
	} else if len(r.Email) > 255 || !emailPattern.MatchString(r.Email) {
		errs.Add("email", "must be a valid email address")
	}

	if r.Password == "" {
		errs.Add("password", "is required")
	} else if !isPasswordComplexEnough(r.Password) {
		errs.Add("password", "must be at least 12 characters and include upper, lower, digit, and symbol")
	}

	return errs.Err()
}

// BootstrapResponse is the 201 body for a successful bootstrap — the same
// shape as RegisterResponse, and for the same reason that type documents:
// no password, password_hash, or token field exists on this struct for a
// secret to ever reach the wire through. The flow is Bootstrap -> Login,
// never an implicit session — this response carries nothing a client
// could use to skip the real login step.
type BootstrapResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}
