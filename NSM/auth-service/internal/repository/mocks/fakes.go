// Package mocks provides hand-written, in-memory fakes for the ports in
// internal/repository — no mocking framework, no code generation. They
// exist purely so internal/service's unit tests can run in milliseconds
// with no database, exercising real business logic (lockout thresholds,
// refresh-token rotation, reuse detection) against a fake that behaves
// like Postgres would, without needing Postgres to be running.
package mocks

import (
	"context"
	"sort"
	"strings"
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
	// FailNextGetByEmail, if non-nil, is returned by the next GetByEmail
	// call instead of the normal lookup, then reset to nil — a fault
	// injection point for exercising "the database itself is unavailable"
	// (a plain internal error, distinct from entity.ErrNotFound) without a
	// real database to actually take down. See
	// internal/service/auth_service_test.go's database-failure test.
	FailNextGetByEmail error
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
	if f.FailNextGetByEmail != nil {
		err := f.FailNextGetByEmail
		f.FailNextGetByEmail = nil
		return nil, err
	}
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
	// FailNextCreate/FailNextGetByID/FailNextRevoke, if non-nil, are
	// returned by the next matching call instead of the normal behavior,
	// then reset to nil — the same fault-injection convention as
	// FakeAuditLogRepository.FailNext and FakeUserRepository.FailNextGetByEmail,
	// used by internal/service/session_service_test.go to exercise
	// "nonexistent user" (a simulated foreign-key violation) and "database
	// unavailable" without a real Postgres to actually break.
	FailNextCreate  error
	FailNextGetByID error
	FailNextRevoke  error
}

func NewFakeSessionRepository() *FakeSessionRepository {
	return &FakeSessionRepository{byID: map[string]*entity.Session{}}
}

// Seed inserts or overwrites a session directly, bypassing Create — the
// natural way a test arranges "given a session already in this state"
// (e.g. one that's already past its expiry), mirroring
// FakeUserRepository.Seed for the same reason.
func (f *FakeSessionRepository) Seed(s *entity.Session) *entity.Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.ID == "" {
		s.ID = util.NewUUID()
	}
	f.byID[s.ID] = s
	return s
}

func (f *FakeSessionRepository) Create(_ context.Context, s *entity.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNextCreate != nil {
		err := f.FailNextCreate
		f.FailNextCreate = nil
		return err
	}
	s.ID = util.NewUUID()
	s.CreatedAt, s.LastActiveAt = time.Now(), time.Now()
	f.byID[s.ID] = s
	return nil
}

func (f *FakeSessionRepository) GetByID(_ context.Context, id string) (*entity.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNextGetByID != nil {
		err := f.FailNextGetByID
		f.FailNextGetByID = nil
		return nil, err
	}
	s, ok := f.byID[id]
	if !ok {
		return nil, entity.ErrNotFound
	}
	cp := *s
	return &cp, nil
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

// Revoke mirrors postgres.sessionRepository.Revoke's
// `WHERE id = $1 AND revoked_at IS NULL` exactly: a session that's already
// revoked matches zero rows in Postgres, translated to entity.ErrNotFound
// by checkRowsAffected, so the fake must fail the same way on a second
// call rather than silently re-revoking — that's what makes
// SessionService.RevokeSession's own idempotency handling meaningfully
// testable against this fake instead of trivially true.
func (f *FakeSessionRepository) Revoke(_ context.Context, id string, reason entity.RevocationReason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNextRevoke != nil {
		err := f.FailNextRevoke
		f.FailNextRevoke = nil
		return err
	}
	s, ok := f.byID[id]
	if !ok || s.RevokedAt != nil {
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
	// FailNextGetByTokenHash/FailNextRotate, if non-nil, are returned by
	// the next matching call instead of the normal behavior, then reset to
	// nil — the same fault-injection convention used throughout this file,
	// for Milestone 5B's "database failure produces a safe error" and
	// reuse-detection tests.
	FailNextGetByTokenHash error
	FailNextRotate         error
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
	if f.FailNextGetByTokenHash != nil {
		err := f.FailNextGetByTokenHash
		f.FailNextGetByTokenHash = nil
		return nil, err
	}
	for _, t := range f.byID {
		if t.TokenHash == hash {
			cp := *t
			return &cp, nil
		}
	}
	return nil, entity.ErrNotFound
}

// Rotate mirrors postgres.refreshTokenRepository.Rotate's
// `WHERE id = $3 AND revoked_at IS NULL` exactly: a token that's already
// revoked (rotated or otherwise) matches zero rows in Postgres, and the
// whole transaction — including the "next" row's INSERT — rolls back with
// it. The fake must fail the same way and must not persist `next` in that
// case, or the concurrency/reuse tests this exists for would pass
// trivially instead of proving anything.
func (f *FakeRefreshTokenRepository) Rotate(_ context.Context, current, next *entity.RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNextRotate != nil {
		err := f.FailNextRotate
		f.FailNextRotate = nil
		return err
	}
	stored, ok := f.byID[current.ID]
	if !ok || stored.RevokedAt != nil {
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

// FakeAuditTx returns a closure structurally identical to
// service.AuditTxFunc — see that type's own doc comment
// (internal/service/auth_service.go) for why a real implementation needs
// database.WithTx at all (the hash-chain advisory lock only serializes
// inside a genuine transaction). This fake needs none of that: it just
// calls fn directly against audit, no snapshot/restore. That's
// deliberate, not a shortcut — every real AuditTxFunc caller in this
// codebase that wraps a best-effort write (recordUserAudit,
// recordLoginAudit, and Sprint 3 Phase 3's SecretService) treats a
// failure here as loggable-and-swallowed, never as a reason to undo the
// primary write it's describing, so there is nothing for this fake to
// roll back to.
func FakeAuditTx(audit *FakeAuditLogRepository) func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
	return func(ctx context.Context, fn func(repository.AuditLogRepository) error) error {
		return fn(audit)
	}
}

// FakeSecretRepository implements repository.SecretRepository over
// in-memory maps — secrets keyed by ID, versions keyed by secret ID —
// mirroring the real schema's two-table split (migrations/000024).
type FakeSecretRepository struct {
	mu       sync.Mutex
	byID     map[string]*entity.Secret
	versions map[string][]*entity.SecretVersion
	// FailNextCreateVersion, if non-nil, is returned by the next
	// CreateWithFirstVersion/CreateVersion/CreateVersionIfCurrent call
	// instead of succeeding, then reset to nil — the same fault-injection
	// convention as FakeAuditLogRepository.FailNext, for exercising "the
	// version write failed, the secret must not be left half-created"
	// without a real database.
	FailNextCreateVersion error
}

func NewFakeSecretRepository() *FakeSecretRepository {
	return &FakeSecretRepository{byID: map[string]*entity.Secret{}, versions: map[string][]*entity.SecretVersion{}}
}

// Seed inserts a secret directly, bypassing Create's ID assignment.
func (f *FakeSecretRepository) Seed(s *entity.Secret) *entity.Secret {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.ID == "" {
		s.ID = util.NewUUID()
	}
	f.byID[s.ID] = s
	return s
}

// SeedVersion inserts a version directly, for tests that need a specific
// historical version present without going through CreateVersion.
func (f *FakeSecretRepository) SeedVersion(v *entity.SecretVersion) *entity.SecretVersion {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v.ID == "" {
		v.ID = util.NewUUID()
	}
	f.versions[v.SecretID] = append(f.versions[v.SecretID], v)
	return v
}

func (f *FakeSecretRepository) Create(_ context.Context, s *entity.Secret) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createLocked(s)
}

// createLocked mirrors uq_secrets_org_path (case-insensitive, like the
// real CITEXT column) so a unit test exercising duplicate-path behavior
// gets the same entity.ErrAlreadyExists a real Postgres unique-violation
// would produce, without needing a database. Caller must hold f.mu.
func (f *FakeSecretRepository) createLocked(s *entity.Secret) error {
	for _, existing := range f.byID {
		if existing.DeletedAt != nil {
			continue
		}
		if existing.OrganizationID == s.OrganizationID && strings.EqualFold(existing.Path, s.Path) {
			return entity.ErrAlreadyExists
		}
	}
	if s.ID == "" {
		s.ID = util.NewUUID()
	}
	s.CreatedAt, s.UpdatedAt = time.Now(), time.Now()
	f.byID[s.ID] = s
	return nil
}

func (f *FakeSecretRepository) GetByID(_ context.Context, id string) (*entity.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok || s.DeletedAt != nil {
		return nil, entity.ErrNotFound
	}
	return s, nil
}

func (f *FakeSecretRepository) GetByPath(_ context.Context, organizationID, path string) (*entity.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.byID {
		if s.DeletedAt == nil && s.OrganizationID == organizationID && strings.EqualFold(s.Path, path) {
			return s, nil
		}
	}
	return nil, entity.ErrNotFound
}

func (f *FakeSecretRepository) List(_ context.Context, organizationID string, _ repository.SecretFilter) ([]*entity.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.Secret
	for _, s := range f.byID {
		if s.DeletedAt == nil && s.OrganizationID == organizationID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (f *FakeSecretRepository) SoftDelete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok || s.DeletedAt != nil {
		return entity.ErrNotFound
	}
	now := time.Now()
	s.DeletedAt, s.UpdatedAt = &now, now
	return nil
}

func (f *FakeSecretRepository) CreateWithFirstVersion(_ context.Context, s *entity.Secret, v *entity.SecretVersion) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNextCreateVersion != nil {
		err := f.FailNextCreateVersion
		f.FailNextCreateVersion = nil
		return err
	}
	if err := f.createLocked(s); err != nil {
		return err
	}
	v.SecretID, v.ID, v.Version, v.CreatedAt = s.ID, util.NewUUID(), 1, time.Now()
	f.versions[s.ID] = []*entity.SecretVersion{v}
	s.CurrentVersion = 1
	return nil
}

func (f *FakeSecretRepository) CreateVersion(_ context.Context, v *entity.SecretVersion) error {
	return f.createVersion(v, 0)
}

func (f *FakeSecretRepository) CreateVersionIfCurrent(_ context.Context, v *entity.SecretVersion, expectedCurrentVersion int) error {
	return f.createVersion(v, expectedCurrentVersion)
}

func (f *FakeSecretRepository) createVersion(v *entity.SecretVersion, expectedCurrentVersion int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNextCreateVersion != nil {
		err := f.FailNextCreateVersion
		f.FailNextCreateVersion = nil
		return err
	}
	s, ok := f.byID[v.SecretID]
	if !ok || s.DeletedAt != nil {
		return entity.ErrNotFound
	}
	if expectedCurrentVersion > 0 && s.CurrentVersion != expectedCurrentVersion {
		return entity.ErrVersionConflict
	}
	next := s.CurrentVersion + 1
	v.ID, v.Version, v.CreatedAt = util.NewUUID(), next, time.Now()
	f.versions[v.SecretID] = append(f.versions[v.SecretID], v)
	s.CurrentVersion, s.UpdatedAt = next, time.Now()
	return nil
}

func (f *FakeSecretRepository) GetVersion(_ context.Context, secretID string, version int) (*entity.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.versions[secretID] {
		if v.Version == version && v.DeletedAt == nil {
			return v, nil
		}
	}
	return nil, entity.ErrNotFound
}

func (f *FakeSecretRepository) GetCurrentVersion(ctx context.Context, secretID string) (*entity.SecretVersion, error) {
	f.mu.Lock()
	s, ok := f.byID[secretID]
	f.mu.Unlock()
	if !ok {
		return nil, entity.ErrNotFound
	}
	return f.GetVersion(ctx, secretID, s.CurrentVersion)
}

func (f *FakeSecretRepository) ListVersions(_ context.Context, secretID string) ([]*entity.SecretVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.SecretVersion
	for _, v := range f.versions[secretID] {
		if v.DeletedAt == nil {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, nil
}

func (f *FakeSecretRepository) SoftDeleteVersion(_ context.Context, secretID string, version int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.versions[secretID] {
		if v.Version == version && v.DeletedAt == nil {
			now := time.Now()
			v.DeletedAt = &now
			return nil
		}
	}
	return entity.ErrNotFound
}

// CountVersionsByKeyID mirrors postgres.secretRepository.CountVersionsByKeyID's
// cross-secret scope — every version of every secret this fake knows
// about, soft-deleted or not, counts if its KeyID matches.
func (f *FakeSecretRepository) CountVersionsByKeyID(_ context.Context, keyID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, versions := range f.versions {
		for _, v := range versions {
			if v.KeyID == keyID {
				count++
			}
		}
	}
	return count, nil
}

// FakeRBACRepository implements repository.RBACRepository over an
// in-memory userID -> granted "resource:action" set — enough for
// internal/service tests to construct a real *service.RBACService (see
// NewRBACService) without a database, the same "fake the port, exercise
// the real service logic" split every other fake in this file follows.
// No rbac_service_test.go existed before Sprint 3 Phase 3 to already
// provide one.
type FakeRBACRepository struct {
	mu    sync.Mutex
	grant map[string]map[string]bool // userID -> "resource:action" -> true
}

func NewFakeRBACRepository() *FakeRBACRepository {
	return &FakeRBACRepository{grant: map[string]map[string]bool{}}
}

// Grant gives userID the given "resource:action" permission — the
// natural way a test arranges "given a user who holds secrets:create."
func (f *FakeRBACRepository) Grant(userID, permission string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grant[userID] == nil {
		f.grant[userID] = map[string]bool{}
	}
	f.grant[userID][permission] = true
}

func (f *FakeRBACRepository) UserHasPermission(_ context.Context, userID, resource, action string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grant[userID][resource+":"+action], nil
}

func (f *FakeRBACRepository) UserPermissions(_ context.Context, userID string) ([]*entity.Permission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.Permission
	for perm := range f.grant[userID] {
		resource, action, _ := strings.Cut(perm, ":")
		out = append(out, &entity.Permission{Resource: resource, Action: action})
	}
	return out, nil
}

func (f *FakeRBACRepository) CountUsersWithRole(_ context.Context, _ string) (int, error) {
	return 0, nil
}
