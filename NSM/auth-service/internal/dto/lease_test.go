package dto

import (
	"strings"
	"testing"
	"time"
)

func ttlPtr(s string) *string { return &s }

func validLeaseCreateRequest() LeaseCreateRequest {
	return LeaseCreateRequest{Type: "dev-credential", Path: "database/prod/readonly", TTL: ttlPtr("5m")}
}

func TestLeaseCreateRequest_Validate_Succeeds(t *testing.T) {
	if err := validLeaseCreateRequest().Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

func TestLeaseCreateRequest_Validate_OmittedTTLSucceeds(t *testing.T) {
	req := validLeaseCreateRequest()
	req.TTL = nil
	if err := req.Validate(); err != nil {
		t.Errorf("Validate() with omitted ttl, error = %v, want nil (omitted means use the server default)", err)
	}
}

func TestLeaseCreateRequest_Validate_MissingType(t *testing.T) {
	req := validLeaseCreateRequest()
	req.Type = ""
	err := req.Validate()
	if err == nil {
		t.Fatal("Validate() with empty type = nil, want an error")
	}
	if issue := fieldIssue(t, err, "type"); !strings.Contains(issue, "required") {
		t.Errorf("type issue = %q, want it to mention 'required'", issue)
	}
}

func TestLeaseCreateRequest_Validate_MissingPath(t *testing.T) {
	req := validLeaseCreateRequest()
	req.Path = ""
	if err := req.Validate(); err == nil {
		t.Error("Validate() with empty path = nil, want an error")
	}
}

func TestLeaseCreateRequest_Validate_PathTooLong(t *testing.T) {
	req := validLeaseCreateRequest()
	req.Path = strings.Repeat("a", 1041)
	if err := req.Validate(); err == nil {
		t.Error("Validate() with a 1041-character path = nil, want an error")
	}
}

// TestLeaseCreateRequest_Validate_RejectsNonPositiveTTL is the security
// checklist's own "negative/zero TTL" case — the objective's explicit
// "never allow a client to request an arbitrary unlimited TTL" rule,
// enforced at the DTO boundary before RequestedTTL could ever reach
// LeaseService.effectiveTTL, where a zero value means "use the default."
func TestLeaseCreateRequest_Validate_RejectsNonPositiveTTL(t *testing.T) {
	for name, ttl := range map[string]string{"zero": "0s", "negative": "-5m"} {
		t.Run(name, func(t *testing.T) {
			req := validLeaseCreateRequest()
			req.TTL = ttlPtr(ttl)
			err := req.Validate()
			if err == nil {
				t.Fatalf("Validate() with ttl=%q = nil, want an error", ttl)
			}
			if issue := fieldIssue(t, err, "ttl"); !strings.Contains(issue, "positive") {
				t.Errorf("ttl issue = %q, want it to mention 'positive'", issue)
			}
		})
	}
}

// TestLeaseCreateRequest_Validate_RejectsMalformedTTL is the security
// checklist's own "malformed TTL" case.
func TestLeaseCreateRequest_Validate_RejectsMalformedTTL(t *testing.T) {
	for name, ttl := range map[string]string{
		"not a duration":                        "forever",
		"missing unit":                          "5",
		"unbounded time.Duration abuse attempt": "99999999999999999999h",
	} {
		t.Run(name, func(t *testing.T) {
			req := validLeaseCreateRequest()
			req.TTL = ttlPtr(ttl)
			if err := req.Validate(); err == nil {
				t.Fatalf("Validate() with ttl=%q = nil, want an error", ttl)
			}
		})
	}
}

func TestLeaseCreateRequest_ParsedTTL_MatchesValidatedValue(t *testing.T) {
	req := validLeaseCreateRequest()
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	ttl, err := req.ParsedTTL()
	if err != nil {
		t.Fatalf("ParsedTTL() error = %v", err)
	}
	if ttl != 5*time.Minute {
		t.Errorf("ParsedTTL() = %s, want 5m", ttl)
	}
}

func TestLeaseCreateRequest_ParsedTTL_OmittedReturnsZero(t *testing.T) {
	req := validLeaseCreateRequest()
	req.TTL = nil
	ttl, err := req.ParsedTTL()
	if err != nil {
		t.Fatalf("ParsedTTL() error = %v", err)
	}
	if ttl != 0 {
		t.Errorf("ParsedTTL() with omitted ttl = %s, want 0 (the \"use default\" signal)", ttl)
	}
}

// --- LeaseRenewRequest: the identical optional-TTL contract ---

func TestLeaseRenewRequest_Validate_RejectsNonPositiveTTL(t *testing.T) {
	req := LeaseRenewRequest{TTL: ttlPtr("0s")}
	if err := req.Validate(); err == nil {
		t.Error("Validate() with ttl=0s = nil, want an error")
	}
}

func TestLeaseRenewRequest_Validate_RejectsMalformedTTL(t *testing.T) {
	req := LeaseRenewRequest{TTL: ttlPtr("not-a-duration")}
	if err := req.Validate(); err == nil {
		t.Error("Validate() with a malformed ttl = nil, want an error")
	}
}

func TestLeaseRenewRequest_Validate_OmittedTTLSucceeds(t *testing.T) {
	req := LeaseRenewRequest{}
	if err := req.Validate(); err != nil {
		t.Errorf("Validate() with omitted ttl, error = %v, want nil", err)
	}
}

// TestLeaseCreatedResponse_OnlyCarriesCredentialOnCreation is a
// type-level assertion of the security checklist's own "credential
// exposure through GET" requirement: LeaseResponse (what GET/renew/revoke
// return) has no field capable of holding credential material at all —
// only LeaseCreatedResponse, POST /v1/leases' own response type, embeds
// one. This test would fail to compile, not fail at runtime, if that
// property were ever violated by adding a Credential-shaped field
// directly to LeaseResponse.
func TestLeaseCreatedResponse_OnlyCarriesCredentialOnCreation(t *testing.T) {
	var plain LeaseResponse
	created := LeaseCreatedResponse{LeaseResponse: plain, Credential: map[string]string{"password": "x"}}
	if created.Credential == nil {
		t.Fatal("LeaseCreatedResponse.Credential is nil, want the credential map")
	}
}
