// Package mocks provides hand-written, in-memory fakes for the ports in
// internal/repository — no mocking framework, no code generation. They
// exist purely so internal/service's unit tests can run in milliseconds
// with no database, exercising real business logic (lockout thresholds,
// refresh-token rotation, reuse detection) against a fake that behaves
// like Postgres would, without needing Postgres to be running.
package mocks

import (
	"context"
	"sync"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// FakeUserRepository implements repository.UserRepository over an
// in-memory map, keyed by ID.
type FakeUserRepository struct {
	mu    sync.Mutex
	byID  map[string]*entity.User
	roles map[string][]*entity.UserRole
}

func NewFakeUserRepository() *FakeUserRepository {
	return &FakeUserRepository{byID: map[string]*entity.User{}, roles: map[string][]*entity.UserRole{}}
}

// Seed inserts a user directly, bypassing Create's ID assignment — the
// natural way a test arranges "given a user who already exists."
func (f *FakeUserRepository) Seed(u *entity.User) *entity.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u.ID == "" {
		u.ID = util.NewUUID()
	}
	f.byID[u.ID] = u
	return u
}

// Create mirrors the two real UNIQUE constraints on the users table
// (uq_users_org_email, uq_users_org_username — see
// migrations/000003_create_users_table.up.sql and
// 000019_add_users_username_unique.up.sql) so a unit test exercising
// duplicate-registration behavior gets the same entity.ErrAlreadyExists a
// real Postgres unique-violation would produce via translateError,
// without needing a database. A nil/empty username never conflicts with
// another nil/empty username, matching Postgres's own NULL-is-distinct
// behavior in a UNIQUE index.
func (f *FakeUserRepository) Create(_ context.Context, u *entity.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.byID {
		if existing.OrganizationID != u.OrganizationID {
			continue
		}
		if existing.Email == u.Email {
			return entity.ErrAlreadyExists
		}
		if u.Username != nil && existing.Username != nil && *existing.Username == *u.Username {
			return entity.ErrAlreadyExists
		}
	}
	u.ID = util.NewUUID()
	u.CreatedAt, u.UpdatedAt = time.Now(), time.Now()
	f.byID[u.ID] = u
	return nil
}

// snapshot/restore give FakeRegistrationTx (below) something to roll back
// to — the same all-or-nothing guarantee a real Postgres transaction
// gives database.WithTx, reproduced here so a unit test can assert
// "failed registration leaves no partial state" without a database.
func (f *FakeUserRepository) snapshot() map[string]*entity.User {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]*entity.User, len(f.byID))
	for k, v := range f.byID {
		u := *v
		cp[k] = &u
	}
	return cp
}

func (f *FakeUserRepository) restore(snapshot map[string]*entity.User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID = snapshot
}

func (f *FakeUserRepository) GetByID(_ context.Context, id string) (*entity.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return nil, entity.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (f *FakeUserRepository) GetByEmail(_ context.Context, organizationID, email string) (*entity.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.byID {
		if u.OrganizationID == organizationID && u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, entity.ErrNotFound
}

func (f *FakeUserRepository) List(_ context.Context, organizationID string, _ repository.UserFilter) ([]*entity.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.User
	for _, u := range f.byID {
		if u.OrganizationID == organizationID {
			cp := *u
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *FakeUserRepository) Update(_ context.Context, u *entity.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byID[u.ID]; !ok {
		return entity.ErrNotFound
	}
	u.UpdatedAt = time.Now()
	f.byID[u.ID] = u
	return nil
}

func (f *FakeUserRepository) SoftDelete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return entity.ErrNotFound
	}
	now := time.Now()
	u.DeletedAt = &now
	return nil
}

func (f *FakeUserRepository) IncrementFailedLoginAttempts(_ context.Context, id string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return 0, entity.ErrNotFound
	}
	u.FailedLoginAttempts++
	return int(u.FailedLoginAttempts), nil
}

func (f *FakeUserRepository) ResetFailedLoginAttempts(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.byID[id]; ok {
		u.FailedLoginAttempts = 0
		u.LockedUntil = nil
	}
	return nil
}

func (f *FakeUserRepository) Lock(_ context.Context, id string, until time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.byID[id]; ok {
		u.LockedUntil = &until
	}
	return nil
}

func (f *FakeUserRepository) GrantRole(_ context.Context, g *entity.UserRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g.AssignedAt = time.Now()
	f.roles[g.UserID] = append(f.roles[g.UserID], g)
	return nil
}

func (f *FakeUserRepository) RevokeRole(_ context.Context, userID, roleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	grants := f.roles[userID]
	for i, g := range grants {
		if g.RoleID == roleID {
			f.roles[userID] = append(grants[:i], grants[i+1:]...)
			return nil
		}
	}
	return entity.ErrNotFound
}

func (f *FakeUserRepository) ListRoles(_ context.Context, userID string) ([]*entity.UserRole, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roles[userID], nil
}

// FakeSessionRepository implements repository.SessionRepository.
type FakeSessionRepository struct {
	mu   sync.Mutex
	byID map[string]*entity.Session
}

func NewFakeSessionRepository() *FakeSessionRepository {
	return &FakeSessionRepository{byID: map[string]*entity.Session{}}
}

func (f *FakeSessionRepository) Create(_ context.Context, s *entity.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s.ID = util.NewUUID()
	s.CreatedAt, s.LastActiveAt = time.Now(), time.Now()
	f.byID[s.ID] = s
	return nil
}

func (f *FakeSessionRepository) GetByID(_ context.Context, id string) (*entity.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok {
		return nil, entity.ErrNotFound
	}
	return s, nil
}

func (f *FakeSessionRepository) GetByTokenHash(_ context.Context, hash string) (*entity.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byID {
		if s.SessionTokenHash == hash {
			return s, nil
		}
	}
	return nil, entity.ErrNotFound
}

func (f *FakeSessionRepository) ListActiveByUser(_ context.Context, userID string) ([]*entity.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.Session
	for _, s := range f.byID {
		if s.UserID == userID && s.IsActive(time.Now()) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *FakeSessionRepository) Touch(_ context.Context, id string, t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.byID[id]; ok {
		s.LastActiveAt = t
	}
	return nil
}

func (f *FakeSessionRepository) Revoke(_ context.Context, id string, reason entity.RevocationReason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok {
		return entity.ErrNotFound
	}
	now := time.Now()
	s.RevokedAt, s.RevokedReason = &now, &reason
	return nil
}

func (f *FakeSessionRepository) RevokeAllForUser(_ context.Context, userID string, reason entity.RevocationReason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for _, s := range f.byID {
		if s.UserID == userID {
			s.RevokedAt, s.RevokedReason = &now, &reason
		}
	}
	return nil
}

// FakeRefreshTokenRepository implements repository.RefreshTokenRepository.
type FakeRefreshTokenRepository struct {
	mu   sync.Mutex
	byID map[string]*entity.RefreshToken
}

func NewFakeRefreshTokenRepository() *FakeRefreshTokenRepository {
	return &FakeRefreshTokenRepository{byID: map[string]*entity.RefreshToken{}}
}

func (f *FakeRefreshTokenRepository) Create(_ context.Context, t *entity.RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t.ID = util.NewUUID()
	t.IssuedAt = time.Now()
	f.byID[t.ID] = t
	return nil
}

func (f *FakeRefreshTokenRepository) GetByTokenHash(_ context.Context, hash string) (*entity.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.byID {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, entity.ErrNotFound
}

func (f *FakeRefreshTokenRepository) Rotate(_ context.Context, current, next *entity.RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored, ok := f.byID[current.ID]
	if !ok {
		return entity.ErrNotFound
	}
	next.ID = util.NewUUID()
	next.IssuedAt = time.Now()
	f.byID[next.ID] = next

	now := time.Now()
	reason := entity.RevocationRotation
	stored.RevokedAt, stored.RevokedReason, stored.ReplacedByTokenID = &now, &reason, &next.ID
	return nil
}

func (f *FakeRefreshTokenRepository) RevokeFamily(_ context.Context, familyID string, reason entity.RevocationReason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for _, t := range f.byID {
		if t.FamilyID == familyID && t.RevokedAt == nil {
			t.RevokedAt, t.RevokedReason = &now, &reason
		}
	}
	return nil
}

// FakeLoginHistoryRepository implements repository.LoginHistoryRepository.
type FakeLoginHistoryRepository struct {
	mu      sync.Mutex
	Entries []*entity.LoginHistoryEntry
}

func NewFakeLoginHistoryRepository() *FakeLoginHistoryRepository {
	return &FakeLoginHistoryRepository{}
}

func (f *FakeLoginHistoryRepository) Record(_ context.Context, e *entity.LoginHistoryEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	e.ID = util.NewUUID()
	e.OccurredAt = time.Now()
	f.Entries = append(f.Entries, e)
	return nil
}

func (f *FakeLoginHistoryRepository) List(_ context.Context, organizationID string, _ repository.LoginHistoryFilter) ([]*entity.LoginHistoryEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.LoginHistoryEntry
	for _, e := range f.Entries {
		if e.OrganizationID != nil && *e.OrganizationID == organizationID {
			out = append(out, e)
		}
	}
	return out, nil
}

// FakeAuditLogRepository implements repository.AuditLogRepository.
// Append reproduces the hash-chain behavior of
// postgres.auditLogRepository.Append (each record's hash covers the
// previous one) without any of the concurrency machinery real Postgres
// needs — a single mutex is a perfectly adequate substitute for
// pg_advisory_xact_lock when there's only ever one goroutine in a test.
type FakeAuditLogRepository struct {
	mu      sync.Mutex
	Entries []*entity.AuditLogEntry
	// FailNext, if non-nil, is returned by the next Append call instead of
	// succeeding, then reset to nil — a deliberate fault injection point
	// for exercising "the audit write failed, so the whole registration
	// must roll back" without needing a real database to actually break.
	FailNext error
}

func NewFakeAuditLogRepository() *FakeAuditLogRepository {
	return &FakeAuditLogRepository{}
}

func (f *FakeAuditLogRepository) Append(_ context.Context, e *entity.AuditLogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNext != nil {
		err := f.FailNext
		f.FailNext = nil
		return err
	}
	if len(f.Entries) > 0 {
		prev := f.Entries[len(f.Entries)-1].RecordHash
		e.PrevHash = &prev
	}
	e.ID = util.NewUUID()
	e.RecordHash = util.NewUUID() // a real hash in postgres.auditLogRepository; identity is all a fake needs
	e.OccurredAt = time.Now()
	f.Entries = append(f.Entries, e)
	return nil
}

func (f *FakeAuditLogRepository) GetByID(_ context.Context, id string) (*entity.AuditLogEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.Entries {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, entity.ErrNotFound
}

func (f *FakeAuditLogRepository) List(_ context.Context, organizationID string, _ repository.AuditLogFilter) ([]*entity.AuditLogEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.AuditLogEntry
	for _, e := range f.Entries {
		if e.OrganizationID != nil && *e.OrganizationID == organizationID {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *FakeAuditLogRepository) LatestHash(_ context.Context, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.Entries) == 0 {
		return "", nil
	}
	return f.Entries[len(f.Entries)-1].RecordHash, nil
}

func (f *FakeAuditLogRepository) snapshot() []*entity.AuditLogEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]*entity.AuditLogEntry, len(f.Entries))
	copy(cp, f.Entries)
	return cp
}

func (f *FakeAuditLogRepository) restore(snapshot []*entity.AuditLogEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Entries = snapshot
}

// FakeRegistrationTx returns a closure structurally identical to
// service.RegistrationTxFunc (Go allows assigning an unnamed func value to
// a named func type with the same underlying signature, so callers don't
// need to import this package's type — they just assign the return value
// directly to a service.RegistrationTxFunc-typed field). It reproduces
// database.WithTx's all-or-nothing guarantee — snapshot both fakes,run fn,
// and roll back to the snapshot on error — so
// internal/service/user_service_test.go can assert "a failed registration
// leaves no partial state" without a real database. That guarantee is
// only really proven by test/integration/register_test.go against actual
// Postgres; this fake proves UserService.Register's own orchestration
// treats the two writes as one unit, which is the half of the guarantee
// that's this package's to prove.
func FakeRegistrationTx(users *FakeUserRepository, audit *FakeAuditLogRepository) func(ctx context.Context, fn func(repository.UserRepository, repository.AuditLogRepository) error) error {
	return func(ctx context.Context, fn func(repository.UserRepository, repository.AuditLogRepository) error) error {
		usersSnapshot := users.snapshot()
		auditSnapshot := audit.snapshot()
		if err := fn(users, audit); err != nil {
			users.restore(usersSnapshot)
			audit.restore(auditSnapshot)
			return err
		}
		return nil
	}
}
