package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/mocks"
	"github.com/acme/auth-service/internal/security"
)

// newTestUserService wires UserService against the same in-memory fakes
// internal/service/auth_service_test.go uses for AuthService — no
// database, real business logic. registerTx here is mocks.FakeRegistrationTx,
// which reproduces database.WithTx's all-or-nothing guarantee against the
// fakes themselves (see that function's doc comment).
func newTestUserService(t *testing.T) (*UserService, *mocks.FakeUserRepository, *mocks.FakeAuditLogRepository) {
	t.Helper()
	users := mocks.NewFakeUserRepository()
	audit := mocks.NewFakeAuditLogRepository()
	passwords := security.NewPasswordService(security.Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32,
	})
	svc := NewUserService(users, passwords, mocks.FakeRegistrationTx(users, audit))
	return svc, users, audit
}

func validRegisterInput() RegisterInput {
	return RegisterInput{
		OrganizationID: "org-1",
		Username:       "marcus.webb",
		Email:          "marcus.webb@acme.com",
		Password:       "Tr0ub4dor&3xample!",
		IPAddress:      "203.0.113.42",
	}
}

// --- successful registration ---

func TestRegister_Success(t *testing.T) {
	svc, users, _ := newTestUserService(t)

	u, err := svc.Register(t.Context(), validRegisterInput())
	if err != nil {
		t.Fatalf("Register() error = %v, want nil", err)
	}
	if u.ID == "" {
		t.Error("Register() returned a user with no ID")
	}
	if u.Status != entity.UserStatusActive {
		t.Errorf("Register() status = %q, want %q", u.Status, entity.UserStatusActive)
	}
	stored, err := users.GetByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("GetByID() after Register() error = %v", err)
	}
	if stored.Email != "marcus.webb@acme.com" {
		t.Errorf("stored email = %q, want the normalized address", stored.Email)
	}
}

// --- email normalization ---

func TestRegister_NormalizesEmail(t *testing.T) {
	svc, _, _ := newTestUserService(t)
	in := validRegisterInput()
	in.Email = "  Marcus.Webb@ACME.com  "

	u, err := svc.Register(t.Context(), in)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if u.Email != "marcus.webb@acme.com" {
		t.Errorf("Register() stored email = %q, want %q", u.Email, "marcus.webb@acme.com")
	}

	// A second registration differing only in case/whitespace must still
	// collide — normalization has to happen before the uniqueness check
	// sees it, not just before display.
	dup := validRegisterInput()
	dup.Username = "different-username"
	dup.Email = "MARCUS.WEBB@acme.com"
	if _, err := svc.Register(t.Context(), dup); !errors.Is(err, entity.ErrAlreadyExists) {
		t.Errorf("Register() with a differently-cased duplicate email, error = %v, want entity.ErrAlreadyExists", err)
	}
}

// --- duplicate email / duplicate username ---

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, _, _ := newTestUserService(t)
	if _, err := svc.Register(t.Context(), validRegisterInput()); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	second := validRegisterInput()
	second.Username = "a-different-username"
	// same email as the first registration

	_, err := svc.Register(t.Context(), second)
	if !errors.Is(err, entity.ErrAlreadyExists) {
		t.Errorf("Register() with a duplicate email, error = %v, want entity.ErrAlreadyExists", err)
	}
}

func TestRegister_DuplicateUsername(t *testing.T) {
	svc, _, _ := newTestUserService(t)
	if _, err := svc.Register(t.Context(), validRegisterInput()); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	second := validRegisterInput()
	second.Email = "a-different-email@acme.com"
	// same username as the first registration

	_, err := svc.Register(t.Context(), second)
	if !errors.Is(err, entity.ErrAlreadyExists) {
		t.Errorf("Register() with a duplicate username, error = %v, want entity.ErrAlreadyExists", err)
	}
}

// --- password is stored only as an Argon2id hash; plaintext never appears ---

func TestRegister_PasswordStoredOnlyAsArgon2idHash(t *testing.T) {
	svc, users, _ := newTestUserService(t)
	in := validRegisterInput()

	u, err := svc.Register(t.Context(), in)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	stored, err := users.GetByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	if stored.PasswordHash == nil {
		t.Fatal("stored user has no PasswordHash at all")
	}
	if !strings.HasPrefix(*stored.PasswordHash, "$argon2id$") {
		t.Errorf("PasswordHash = %q, want it to start with \"$argon2id$\"", *stored.PasswordHash)
	}
	if stored.PasswordAlgo == nil || *stored.PasswordAlgo != "argon2id" {
		t.Errorf("PasswordAlgo = %v, want \"argon2id\"", stored.PasswordAlgo)
	}
	if *stored.PasswordHash == in.Password {
		t.Error("PasswordHash equals the plaintext password verbatim")
	}
}

func TestRegister_PlaintextPasswordNotInStoredData(t *testing.T) {
	svc, users, _ := newTestUserService(t)
	in := validRegisterInput()

	u, err := svc.Register(t.Context(), in)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	stored, err := users.GetByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}

	// Walk every string-shaped field on the stored entity — not just
	// PasswordHash — so this test still catches the plaintext leaking
	// somewhere unexpected (e.g. a future field added carelessly), not
	// just confirms the one field it's specifically checking today.
	fields := []string{stored.Email, stored.ID, stored.OrganizationID}
	if stored.Username != nil {
		fields = append(fields, *stored.Username)
	}
	if stored.PasswordHash != nil {
		fields = append(fields, *stored.PasswordHash)
	}
	for _, f := range fields {
		if strings.Contains(f, in.Password) {
			t.Errorf("stored field %q contains the plaintext password", f)
		}
	}
}

// --- audit event created for successful registration ---

func TestRegister_AuditEventCreated(t *testing.T) {
	svc, _, audit := newTestUserService(t)
	in := validRegisterInput()

	u, err := svc.Register(t.Context(), in)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if len(audit.Entries) != 1 {
		t.Fatalf("audit.Entries has %d entries, want exactly 1", len(audit.Entries))
	}
	entry := audit.Entries[0]
	if entry.Action != "user.registered" {
		t.Errorf("audit action = %q, want %q", entry.Action, "user.registered")
	}
	if entry.ActorID == nil || *entry.ActorID != u.ID {
		t.Errorf("audit actor_id = %v, want %q", entry.ActorID, u.ID)
	}
	if entry.Result != entity.AuditResultSuccess {
		t.Errorf("audit result = %q, want %q", entry.Result, entity.AuditResultSuccess)
	}
	if entry.IPAddress == nil || *entry.IPAddress != in.IPAddress {
		t.Errorf("audit ip_address = %v, want %q", entry.IPAddress, in.IPAddress)
	}

	// The requirement this test exists to enforce, checked directly:
	// nothing in Metadata may be, or contain, the plaintext password or
	// the stored hash.
	for k, v := range entry.Metadata {
		if strings.EqualFold(k, "password") || strings.EqualFold(k, "password_hash") || strings.EqualFold(k, "hash") {
			t.Errorf("audit metadata has a key named %q — must never carry a password or hash", k)
		}
		if s, ok := v.(string); ok && strings.Contains(s, in.Password) {
			t.Errorf("audit metadata[%q] = %q contains the plaintext password", k, s)
		}
	}
}

// --- failed registration leaves no partial state ---

func TestRegister_FailedRegistrationLeavesNoPartialState(t *testing.T) {
	svc, users, audit := newTestUserService(t)
	audit.FailNext = errors.New("simulated audit-log write failure")

	_, err := svc.Register(t.Context(), validRegisterInput())
	if err == nil {
		t.Fatal("Register() with a forced audit-write failure = nil error, want one")
	}

	all, listErr := users.List(t.Context(), "org-1", repository.UserFilter{})
	if listErr != nil {
		t.Fatalf("List() error = %v", listErr)
	}
	if len(all) != 0 {
		t.Errorf("users repository has %d rows after a failed registration, want 0 (the Create must have rolled back)", len(all))
	}
	if len(audit.Entries) != 0 {
		t.Errorf("audit repository has %d rows after a failed registration, want 0", len(audit.Entries))
	}

	// And the account is genuinely available again — not left in some
	// half-reserved state that would make a retry incorrectly bounce off
	// a duplicate-email error.
	if _, err := svc.Register(t.Context(), validRegisterInput()); err != nil {
		t.Errorf("Register() retried after a rolled-back failure, error = %v, want nil", err)
	}
}
