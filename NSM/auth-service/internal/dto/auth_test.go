package dto

import (
	"encoding/json"
	"strings"
	"testing"
)

func fieldIssue(t *testing.T, err error, field string) string {
	t.Helper()
	fields, ok := Fields(err)
	if !ok {
		t.Fatalf("Validate() error = %v, want a ValidationErrors-backed error", err)
	}
	for _, f := range fields {
		if f.Field == field {
			return f.Issue
		}
	}
	t.Fatalf("Validate() errors = %+v, want an entry for field %q", fields, field)
	return ""
}

func validRegisterRequest() RegisterRequest {
	return RegisterRequest{
		Username: "marcus.webb",
		Email:    "marcus.webb@acme.com",
		Password: "Tr0ub4dor&3xample!",
	}
}

func TestRegisterRequest_Validate_Succeeds(t *testing.T) {
	if err := validRegisterRequest().Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

func TestRegisterRequest_Validate_MissingUsername(t *testing.T) {
	req := validRegisterRequest()
	req.Username = ""

	err := req.Validate()
	if err == nil {
		t.Fatal("Validate() with empty username = nil, want an error")
	}
	if issue := fieldIssue(t, err, "username"); !strings.Contains(issue, "required") {
		t.Errorf("username issue = %q, want it to mention 'required'", issue)
	}
}

func TestRegisterRequest_Validate_InvalidUsername(t *testing.T) {
	tests := map[string]string{
		"too short":        "ab",
		"contains a space": "marcus webb",
		"contains @":       "marcus@webb",
		"over 100 chars":   strings.Repeat("a", 101),
	}
	for name, username := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRegisterRequest()
			req.Username = username
			if err := req.Validate(); err == nil {
				t.Errorf("Validate() with username %s = nil, want a validation error", name)
			}
		})
	}
}

func TestRegisterRequest_Validate_InvalidEmail(t *testing.T) {
	tests := map[string]string{
		"empty":          "",
		"no @":           "marcus.webb-acme.com",
		"no domain":      "marcus.webb@",
		"has whitespace": "marcus webb@acme.com",
	}
	for name, email := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRegisterRequest()
			req.Email = email
			err := req.Validate()
			if err == nil {
				t.Fatalf("Validate() with email %s = nil, want an error", name)
			}
			fieldIssue(t, err, "email")
		})
	}
}

func TestRegisterRequest_Validate_InvalidPassword(t *testing.T) {
	tests := map[string]string{
		"empty":        "",
		"too short":    "Sh0rt&1",
		"no uppercase": "lowercase123!!!!",
		"no digit":     "NoDigitsHere!!!!",
		"no symbol":    "NoSymbolsHere1234",
	}
	for name, password := range tests {
		t.Run(name, func(t *testing.T) {
			req := validRegisterRequest()
			req.Password = password
			err := req.Validate()
			if err == nil {
				t.Fatalf("Validate() with password %s = nil, want an error", name)
			}
			fieldIssue(t, err, "password")
		})
	}
}

func TestRegisterRequest_Validate_ReportsEveryFieldAtOnce(t *testing.T) {
	req := RegisterRequest{} // every field missing
	err := req.Validate()
	fields, ok := Fields(err)
	if !ok {
		t.Fatalf("Validate() error = %v, want a ValidationErrors-backed error", err)
	}
	if len(fields) != 3 {
		t.Errorf("Validate() with every field empty reported %d issues, want 3 (one per field): %+v", len(fields), fields)
	}
}

// --- LoginRequest ---

func validLoginRequest() LoginRequest {
	return LoginRequest{Email: "marcus.webb@acme.com", Password: "Tr0ub4dor&3xample!"}
}

func TestLoginRequest_Validate_Succeeds(t *testing.T) {
	if err := validLoginRequest().Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

func TestLoginRequest_Validate_InvalidEmail(t *testing.T) {
	tests := map[string]string{
		"empty":          "",
		"no @":           "marcus.webb-acme.com",
		"no domain":      "marcus.webb@",
		"has whitespace": "marcus webb@acme.com",
	}
	for name, email := range tests {
		t.Run(name, func(t *testing.T) {
			req := validLoginRequest()
			req.Email = email
			err := req.Validate()
			if err == nil {
				t.Fatalf("Validate() with email %s = nil, want an error", name)
			}
			fieldIssue(t, err, "email")
		})
	}
}

func TestLoginRequest_Validate_MissingPassword(t *testing.T) {
	req := validLoginRequest()
	req.Password = ""

	err := req.Validate()
	if err == nil {
		t.Fatal("Validate() with empty password = nil, want an error")
	}
	if issue := fieldIssue(t, err, "password"); !strings.Contains(issue, "required") {
		t.Errorf("password issue = %q, want it to mention 'required'", issue)
	}
}

// TestLoginRequest_Validate_PasswordComplexityNotEnforced pins the
// deliberate difference from RegisterRequest.Validate: login only checks
// that a password was supplied, never its shape — see LoginRequest.Validate's
// own doc comment for why (complexity is a signup/reset-time rule, and a
// weak password stored under an old policy must still be able to log in).
func TestLoginRequest_Validate_PasswordComplexityNotEnforced(t *testing.T) {
	req := validLoginRequest()
	req.Password = "short"
	if err := req.Validate(); err != nil {
		t.Errorf("Validate() with a short (but non-empty) password = %v, want nil", err)
	}
}

func TestRegisterResponse_NeverEncodesPasswordFields(t *testing.T) {
	// A structural guarantee, asserted rather than just assumed: there is
	// no field on RegisterResponse whose JSON tag could ever contain
	// "password" or "hash" — see the type's own doc comment for why that's
	// by omission, not a json:"-" tag a future edit could remove.
	resp := RegisterResponse{ID: "u1", Username: "marcus.webb", Email: "marcus.webb@acme.com", Status: "active"}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal RegisterResponse: %v", err)
	}
	lower := strings.ToLower(string(data))
	if strings.Contains(lower, "password") || strings.Contains(lower, "hash") {
		t.Errorf("RegisterResponse JSON = %s, must never contain \"password\" or \"hash\"", data)
	}
}
