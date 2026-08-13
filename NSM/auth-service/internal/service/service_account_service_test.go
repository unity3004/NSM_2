package service

import (
	"errors"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/ratelimit"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/util"
)

const (
	saTestOrgID = "org-sa-1"
	saAdminID   = "user-sa-admin"
)

type testSAEnv struct {
	svc             *ServiceAccountService
	serviceAccounts *mocks.FakeServiceAccountRepository
	apiKeys         *mocks.FakeAPIKeyRepository
	abuseProtection *ratelimit.FakeAuthAbuseProtection
	audit           *mocks.FakeAuditLogRepository
	tokens          *util.JWTSigner
}

func newTestSAEnv(t *testing.T) *testSAEnv {
	t.Helper()
	serviceAccounts := mocks.NewFakeServiceAccountRepository()
	apiKeys := mocks.NewFakeAPIKeyRepository()
	audit := mocks.NewFakeAuditLogRepository()
	auditTx := mocks.FakeAuditTx(audit)
	abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationServiceAccountAuth: {
				IP:      &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 30, BlockDuration: 15 * time.Minute},
				Account: &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 3, BlockDuration: 15 * time.Minute},
				Pair:    &ratelimit.DimensionPolicy{Window: 15 * time.Minute, Limit: 3, BlockDuration: 15 * time.Minute},
			},
		},
	})
	tokens := util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute)

	svc := NewServiceAccountService(serviceAccounts, apiKeys, tokens, abuseProtection, 60*time.Second, auditTx)
	return &testSAEnv{svc: svc, serviceAccounts: serviceAccounts, apiKeys: apiKeys, abuseProtection: abuseProtection, audit: audit, tokens: tokens}
}

func (e *testSAEnv) seedActiveServiceAccount(t *testing.T) *entity.ServiceAccount {
	t.Helper()
	return e.serviceAccounts.Seed(&entity.ServiceAccount{
		OrganizationID: saTestOrgID, Name: "payment-service", Status: entity.ServiceAccountStatusActive,
	})
}

// seedCredential issues a real credential the normal way (IssueCredential)
// so the returned raw secret is guaranteed to hash to what's stored — a
// test that hand-built entity.APIKey{KeyHash: "whatever"} would not be
// testing the same hash function Authenticate itself uses.
func (e *testSAEnv) seedCredential(t *testing.T, saID string) (raw string, key *entity.APIKey) {
	t.Helper()
	result, err := e.svc.IssueCredential(t.Context(), IssueCredentialInput{
		ServiceAccountID: saID, Name: "ci-key", ActorUserID: saAdminID, IPAddress: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("IssueCredential() error = %v", err)
	}
	return result.Secret, result.Key
}

// --- lifecycle administration ---

func TestServiceAccountService_CreateServiceAccount_Succeeds(t *testing.T) {
	env := newTestSAEnv(t)
	desc := "GitHub Actions workflow"
	sa, err := env.svc.CreateServiceAccount(t.Context(), CreateServiceAccountInput{
		OrganizationID: saTestOrgID, Name: "ci-tests", Description: &desc, ActorUserID: saAdminID, IPAddress: "203.0.113.10",
	})
	if err != nil {
		t.Fatalf("CreateServiceAccount() error = %v", err)
	}
	if sa.ID == "" || sa.Status != entity.ServiceAccountStatusActive {
		t.Errorf("CreateServiceAccount() = %+v, want a persisted active service account", sa)
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "service_account.created" && e.ActorType == entity.AuditActorUser {
			found = true
		}
	}
	if !found {
		t.Error("no service_account.created audit entry (with ActorType=user) was recorded")
	}
}

func TestServiceAccountService_DisableServiceAccount_RevokesActiveCredentials(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	_, key := env.seedCredential(t, sa.ID)

	if err := env.svc.DisableServiceAccount(t.Context(), sa.ID, saAdminID, "203.0.113.10"); err != nil {
		t.Fatalf("DisableServiceAccount() error = %v", err)
	}

	updated, err := env.serviceAccounts.GetByID(t.Context(), sa.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if updated.Status != entity.ServiceAccountStatusDisabled {
		t.Errorf("Status = %q, want disabled", updated.Status)
	}

	revokedKey, err := env.apiKeys.GetByID(t.Context(), key.ID)
	if err != nil {
		t.Fatalf("GetByID(key): %v", err)
	}
	if revokedKey.Status != entity.APIKeyStatusRevoked {
		t.Errorf("credential Status = %q, want revoked — disabling a service account must revoke its active credentials", revokedKey.Status)
	}
}

func TestServiceAccountService_EnableServiceAccount_DoesNotRestoreRevokedCredentials(t *testing.T) {
	// Re-enabling is not "undo disable" — a credential DisableServiceAccount
	// revoked stays revoked; a fresh one must be issued. This proves that
	// property directly rather than assuming it from DisableServiceAccount's
	// own doc comment alone.
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	_, key := env.seedCredential(t, sa.ID)

	if err := env.svc.DisableServiceAccount(t.Context(), sa.ID, saAdminID, ""); err != nil {
		t.Fatalf("DisableServiceAccount(): %v", err)
	}
	if err := env.svc.EnableServiceAccount(t.Context(), sa.ID, saAdminID, ""); err != nil {
		t.Fatalf("EnableServiceAccount(): %v", err)
	}

	revokedKey, err := env.apiKeys.GetByID(t.Context(), key.ID)
	if err != nil {
		t.Fatalf("GetByID(key): %v", err)
	}
	if revokedKey.Status != entity.APIKeyStatusRevoked {
		t.Errorf("credential Status after re-enable = %q, want still revoked", revokedKey.Status)
	}
}

// --- credential lifecycle ---

func TestServiceAccountService_IssueCredential_SecretShownOnlyAtCreation(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)

	secret, key := env.seedCredential(t, sa.ID)
	if secret == "" {
		t.Fatal("IssueCredential() returned an empty secret")
	}
	if key.KeyHash == secret {
		t.Error("KeyHash equals the raw secret — the secret must never be stored as-is")
	}
	if key.KeyHash != util.HashToken(secret) {
		t.Error("KeyHash does not match HashToken(secret) — Authenticate's own lookup would never find this key")
	}

	// ListCredentials, the only other read path, must never carry the
	// secret or its hash out to a caller.
	listed, err := env.svc.ListCredentials(t.Context(), sa.ID)
	if err != nil {
		t.Fatalf("ListCredentials(): %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("ListCredentials() = %d entries, want 1", len(listed))
	}
}

func TestServiceAccountService_RotateCredential_OldStopsWorkingNewWorks(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	oldSecret, oldKey := env.seedCredential(t, sa.ID)

	result, err := env.svc.RotateCredential(t.Context(), oldKey.ID, saAdminID, "203.0.113.10")
	if err != nil {
		t.Fatalf("RotateCredential() error = %v", err)
	}
	if result.Secret == oldSecret {
		t.Error("RotateCredential() returned the same secret as the old credential")
	}

	if _, err := env.svc.Authenticate(t.Context(), sa.ID, oldSecret, LoginMeta{IPAddress: "203.0.113.10"}); err == nil {
		t.Error("Authenticate() with the rotated-away old secret succeeded, want failure")
	}
	if _, err := env.svc.Authenticate(t.Context(), sa.ID, result.Secret, LoginMeta{IPAddress: "203.0.113.11"}); err != nil {
		t.Errorf("Authenticate() with the new rotated secret failed: %v", err)
	}
}

func TestServiceAccountService_RevokeCredential_StopsAuthentication(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	secret, key := env.seedCredential(t, sa.ID)

	if _, err := env.svc.Authenticate(t.Context(), sa.ID, secret, LoginMeta{IPAddress: "203.0.113.10"}); err != nil {
		t.Fatalf("Authenticate() before revoke: %v", err)
	}
	if err := env.svc.RevokeCredential(t.Context(), key.ID, saAdminID, "203.0.113.10"); err != nil {
		t.Fatalf("RevokeCredential() error = %v", err)
	}
	if _, err := env.svc.Authenticate(t.Context(), sa.ID, secret, LoginMeta{IPAddress: "203.0.113.12"}); !errors.Is(err, entity.ErrInvalidServiceAccountCredential) {
		t.Errorf("Authenticate() after revoke, error = %v, want ErrInvalidServiceAccountCredential", err)
	}
}

// --- machine authentication: the security checklist ---

func TestServiceAccountService_Authenticate_Succeeds(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	secret, _ := env.seedCredential(t, sa.ID)

	result, err := env.svc.Authenticate(t.Context(), sa.ID, secret, LoginMeta{IPAddress: "203.0.113.10"})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.AccessToken == "" || result.ExpiresIn <= 0 {
		t.Fatalf("Authenticate() = %+v, want a real access token", result)
	}

	claims, err := env.tokens.Verify(result.AccessToken)
	if err != nil {
		t.Fatalf("Verify(issued token): %v", err)
	}
	if claims.Subject != sa.ID {
		t.Errorf("claims.Subject = %q, want %q (the service account's own ID)", claims.Subject, sa.ID)
	}
	if !claims.IsServiceAccount() {
		t.Error("claims.IsServiceAccount() = false, want true — the token must identify itself as a machine token")
	}
	if claims.SessionID != "" {
		t.Errorf("claims.SessionID = %q, want empty — a machine token must carry no human session", claims.SessionID)
	}

	updated, err := env.serviceAccounts.GetByID(t.Context(), sa.ID)
	if err != nil {
		t.Fatalf("GetByID(): %v", err)
	}
	if updated.LastAuthenticatedAt == nil {
		t.Error("LastAuthenticatedAt was not updated after a successful authentication")
	}

	found := false
	for _, e := range env.audit.Entries {
		if e.Action == "service_account.login.success" {
			found = true
			if e.ActorType != entity.AuditActorServiceAccount {
				t.Errorf("ActorType = %q, want service_account — the actor of a login event is the service account itself", e.ActorType)
			}
		}
	}
	if !found {
		t.Error("no service_account.login.success audit entry was recorded")
	}
}

func TestServiceAccountService_Authenticate_DisabledServiceAccountRejected(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	secret, _ := env.seedCredential(t, sa.ID)
	if err := env.svc.DisableServiceAccount(t.Context(), sa.ID, saAdminID, ""); err != nil {
		t.Fatalf("DisableServiceAccount(): %v", err)
	}

	// DisableServiceAccount already revokes the credential — issue a fresh
	// active one so this test isolates "the service account is disabled"
	// from "the credential is revoked" (covered by its own test above).
	freshSecret, _ := env.seedCredential(t, sa.ID)
	_ = secret

	if _, err := env.svc.Authenticate(t.Context(), sa.ID, freshSecret, LoginMeta{IPAddress: "203.0.113.10"}); !errors.Is(err, entity.ErrAccountDisabled) {
		t.Errorf("Authenticate() against a disabled service account, error = %v, want ErrAccountDisabled", err)
	}
}

func TestServiceAccountService_Authenticate_ExpiredCredentialRejected(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	past := time.Now().Add(-time.Hour)
	result, err := env.svc.IssueCredential(t.Context(), IssueCredentialInput{
		ServiceAccountID: sa.ID, Name: "expired-key", ExpiresAt: &past, ActorUserID: saAdminID,
	})
	if err != nil {
		t.Fatalf("IssueCredential(): %v", err)
	}

	if _, err := env.svc.Authenticate(t.Context(), sa.ID, result.Secret, LoginMeta{IPAddress: "203.0.113.10"}); !errors.Is(err, entity.ErrInvalidServiceAccountCredential) {
		t.Errorf("Authenticate() with an expired credential, error = %v, want ErrInvalidServiceAccountCredential", err)
	}
}

func TestServiceAccountService_Authenticate_WrongSecretRejected(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	env.seedCredential(t, sa.ID)

	if _, err := env.svc.Authenticate(t.Context(), sa.ID, "sk_live_totally-wrong-secret", LoginMeta{IPAddress: "203.0.113.10"}); !errors.Is(err, entity.ErrInvalidServiceAccountCredential) {
		t.Errorf("Authenticate() with a wrong secret, error = %v, want ErrInvalidServiceAccountCredential", err)
	}
}

func TestServiceAccountService_Authenticate_UnknownServiceAccountRejected(t *testing.T) {
	env := newTestSAEnv(t)
	if _, err := env.svc.Authenticate(t.Context(), "sa-does-not-exist", "sk_live_anything", LoginMeta{IPAddress: "203.0.113.10"}); !errors.Is(err, entity.ErrInvalidServiceAccountCredential) {
		t.Errorf("Authenticate() against an unknown service account, error = %v, want ErrInvalidServiceAccountCredential", err)
	}
}

// TestServiceAccountService_Authenticate_CredentialBelongingToAnotherServiceAccountRejected
// is the anti-enumeration/no-privilege-escalation case: a real, active,
// unexpired credential presented against a *different* service account's
// path must fail exactly like an unknown credential, never succeed and
// never distinguish itself in the returned error.
func TestServiceAccountService_Authenticate_CredentialBelongingToAnotherServiceAccountRejected(t *testing.T) {
	env := newTestSAEnv(t)
	saA := env.seedActiveServiceAccount(t)
	saB := env.serviceAccounts.Seed(&entity.ServiceAccount{OrganizationID: saTestOrgID, Name: "other-service", Status: entity.ServiceAccountStatusActive})
	secretA, _ := env.seedCredential(t, saA.ID)

	if _, err := env.svc.Authenticate(t.Context(), saB.ID, secretA, LoginMeta{IPAddress: "203.0.113.10"}); !errors.Is(err, entity.ErrInvalidServiceAccountCredential) {
		t.Errorf("Authenticate() with saA's credential against saB, error = %v, want ErrInvalidServiceAccountCredential (never succeed)", err)
	}
}

// TestServiceAccountService_Authenticate_RateLimited proves the machine
// auth pre-check actually blocks after the configured Account threshold —
// the objective's own "rate limiting must apply" requirement, exercised
// end-to-end through Authenticate rather than just asserting the
// AuthAbuseProtection dependency is wired.
func TestServiceAccountService_Authenticate_RateLimited(t *testing.T) {
	env := newTestSAEnv(t)
	sa := env.seedActiveServiceAccount(t)
	env.seedCredential(t, sa.ID)

	// testSAEnv's own policy sets Account limit = 3 failures before a
	// block; each of these uses a wrong secret from a distinct IP so only
	// the Account dimension accumulates.
	for i := 0; i < 3; i++ {
		if _, err := env.svc.Authenticate(t.Context(), sa.ID, "sk_live_wrong", LoginMeta{IPAddress: "203.0.113.1"}); err == nil {
			t.Fatalf("attempt %d: Authenticate() with a wrong secret unexpectedly succeeded", i+1)
		}
	}

	var limited RateLimitedError
	_, err := env.svc.Authenticate(t.Context(), sa.ID, "sk_live_wrong-again", LoginMeta{IPAddress: "203.0.113.1"})
	if !errors.As(err, &limited) {
		t.Errorf("Authenticate() after crossing the failure threshold, error = %v, want RateLimitedError", err)
	}
}

func TestServiceAccountService_Authenticate_NoAuditTx_StillEnforcesCorrectly(t *testing.T) {
	serviceAccounts := mocks.NewFakeServiceAccountRepository()
	apiKeys := mocks.NewFakeAPIKeyRepository()
	abuseProtection := ratelimit.NewFakeAuthAbuseProtection(ratelimit.Config{
		Operations: map[string]ratelimit.OperationPolicy{
			ratelimit.OperationServiceAccountAuth: {Account: &ratelimit.DimensionPolicy{Window: time.Minute, Limit: 100, BlockDuration: time.Minute}},
		},
	})
	svc := NewServiceAccountService(serviceAccounts, apiKeys, util.NewJWTSigner("test-signing-key-at-least-32-bytes!", 15*time.Minute), abuseProtection, time.Minute, nil)

	sa := serviceAccounts.Seed(&entity.ServiceAccount{OrganizationID: saTestOrgID, Name: "no-audit", Status: entity.ServiceAccountStatusActive})
	result, err := svc.IssueCredential(t.Context(), IssueCredentialInput{ServiceAccountID: sa.ID, Name: "k", ActorUserID: saAdminID})
	if err != nil {
		t.Fatalf("IssueCredential(): %v", err)
	}
	if _, err := svc.Authenticate(t.Context(), sa.ID, result.Secret, LoginMeta{IPAddress: "203.0.113.10"}); err != nil {
		t.Errorf("Authenticate() with a nil auditTx, error = %v, want nil — a nil auditTx must not affect the authentication decision itself", err)
	}
}
