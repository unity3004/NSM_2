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

// List applies every AuditLogFilter field the real
// postgres.auditLogRepository.List does (Sprint 4 Task 3), against the
// in-memory slice instead of SQL — so internal/service's own unit tests
// can exercise real filtering/pagination logic without a database. Sort
// order matches the real repository's ORDER BY occurred_at DESC exactly;
// ties are broken by append order (stable sort), the fake's own
// substitute for the real implementation's ", id DESC" tiebreaker (a
// fake UUID id here carries no ordering information a real BIGSERIAL
// id does — see Append's own comment on why RecordHash is a UUID rather
// than a real hash). Cursor pagination is by ID lookup (find the row the
// cursor names, resume immediately after it in this same ordering) —
// simpler than replicating a row-value comparison, and sufficient for
// what a fake needs to prove: that AuditService's own limit+1/trim/
// encode-cursor logic behaves correctly against *a* correctly-ordered,
// correctly-filtered page boundary. The real (occurred_at, id) row-value
// keyset comparison's own correctness is proven separately, against real
// Postgres, by test/integration/audit_repository_test.go.
func (f *FakeAuditLogRepository) List(_ context.Context, organizationID string, filter repository.AuditLogFilter) ([]*entity.AuditLogEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ordered := make([]*entity.AuditLogEntry, len(f.Entries))
	copy(ordered, f.Entries)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].OccurredAt.After(ordered[j].OccurredAt) })

	startIdx := 0
	if filter.Cursor != nil && *filter.Cursor != "" {
		_, cursorID, err := util.DecodeCursor(*filter.Cursor)
		if err != nil {
			return nil, err
		}
		for i, e := range ordered {
			if e.ID == cursorID {
				startIdx = i + 1
				break
			}
		}
	}

	var out []*entity.AuditLogEntry
	for _, e := range ordered[startIdx:] {
		if !auditEntryMatchesFilter(e, organizationID, filter) {
			continue
		}
		out = append(out, e)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

// auditEntryMatchesFilter is List's own per-entry predicate, factored out
// so CountByResult below can apply the identical filter (everything
// except Cursor/Limit, which List alone applies) without drifting out of
// sync with it.
func auditEntryMatchesFilter(e *entity.AuditLogEntry, organizationID string, filter repository.AuditLogFilter) bool {
	if e.OrganizationID == nil || *e.OrganizationID != organizationID {
		return false
	}
	if filter.ActorType != nil && e.ActorType != *filter.ActorType {
		return false
	}
	if filter.ActorID != nil && (e.ActorID == nil || *e.ActorID != *filter.ActorID) {
		return false
	}
	if filter.Action != nil && e.Action != *filter.Action {
		return false
	}
	if filter.ResourceType != nil && (e.ResourceType == nil || *e.ResourceType != *filter.ResourceType) {
		return false
	}
	if filter.ResourceID != nil {
		// Mirrors postgres.whereClauseForFilter's own resource_id OR
		// metadata->>'path' OR metadata->>'resource_path' match — see
		// that function's own doc comment for why.
		want := *filter.ResourceID
		matchesID := e.ResourceID != nil && *e.ResourceID == want
		matchesPath := false
		if s, ok := e.Metadata["path"].(string); ok && s == want {
			matchesPath = true
		}
		if s, ok := e.Metadata["resource_path"].(string); ok && s == want {
			matchesPath = true
		}
		if !matchesID && !matchesPath {
			return false
		}
	}
	if filter.Result != nil && e.Result != *filter.Result {
		return false
	}
	if filter.RequestID != nil && (e.RequestID == nil || *e.RequestID != *filter.RequestID) {
		return false
	}
	if filter.OccurredAfter != nil && e.OccurredAt.Before(*filter.OccurredAfter) {
		return false
	}
	if filter.OccurredBefore != nil && !e.OccurredAt.Before(*filter.OccurredBefore) {
		return false
	}
	return true
}

func (f *FakeAuditLogRepository) CountByResult(_ context.Context, organizationID string, filter repository.AuditLogFilter) (map[entity.AuditResult]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	counts := make(map[entity.AuditResult]int, 3)
	for _, e := range f.Entries {
		if auditEntryMatchesFilter(e, organizationID, filter) {
			counts[e.Result]++
		}
	}
	return counts, nil
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

// ServiceAccountHasPermission/ServiceAccountPermissions (Sprint 5 Task 1)
// share the same userID/serviceAccountID -> "resource:action" map
// UserHasPermission/UserPermissions already use — this fake makes no
// user_roles-vs-service_account_roles distinction at all (there is no
// second table here to separate), the same "the fake doesn't need the
// real schema's own separation to still exercise real service logic"
// property every other fake in this file already has. Grant (not a
// separately named GrantServiceAccount) is what a test calls either way;
// the ID's own meaning is entirely up to the calling test.
func (f *FakeRBACRepository) ServiceAccountHasPermission(_ context.Context, serviceAccountID, resource, action string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grant[serviceAccountID][resource+":"+action], nil
}

func (f *FakeRBACRepository) ServiceAccountPermissions(_ context.Context, serviceAccountID string) ([]*entity.Permission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.Permission
	for perm := range f.grant[serviceAccountID] {
		resource, action, _ := strings.Cut(perm, ":")
		out = append(out, &entity.Permission{Resource: resource, Action: action})
	}
	return out, nil
}

func (f *FakeRBACRepository) CountUsersWithRole(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// FakeSecretPolicyRepository implements repository.SecretPolicyRepository
// over in-memory maps — the same "fake the port, exercise real service
// logic" split every other fake in this file follows, this time for
// Sprint 4 Task 2's path-authorization schema.
type FakeSecretPolicyRepository struct {
	mu          sync.Mutex
	policies    map[string]*entity.SecretPolicy
	rules       map[string][]*entity.SecretPolicyRule // policyID -> rules
	assignments map[string]map[string]bool            // policyID -> roleID -> true
}

func NewFakeSecretPolicyRepository() *FakeSecretPolicyRepository {
	return &FakeSecretPolicyRepository{
		policies:    map[string]*entity.SecretPolicy{},
		rules:       map[string][]*entity.SecretPolicyRule{},
		assignments: map[string]map[string]bool{},
	}
}

// SeedPolicy inserts p directly, assigning an ID if it doesn't have one —
// the natural way a test arranges "given a policy that already exists."
func (f *FakeSecretPolicyRepository) SeedPolicy(p *entity.SecretPolicy) *entity.SecretPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.ID == "" {
		p.ID = util.NewUUID()
	}
	f.policies[p.ID] = p
	return p
}

// SeedRule attaches a rule to policyID, assigning an ID if it doesn't
// have one.
func (f *FakeSecretPolicyRepository) SeedRule(policyID string, rule *entity.SecretPolicyRule) *entity.SecretPolicyRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rule.ID == "" {
		rule.ID = util.NewUUID()
	}
	rule.PolicyID = policyID
	f.rules[policyID] = append(f.rules[policyID], rule)
	return rule
}

// AssignRole assigns policyID to roleID directly, bypassing the RBAC
// permission check AssignToRole's real caller (SecretPolicyService)
// would otherwise enforce — the natural way a test arranges "given a
// role that already holds this policy."
func (f *FakeSecretPolicyRepository) AssignRole(policyID, roleID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.assignments[policyID] == nil {
		f.assignments[policyID] = map[string]bool{}
	}
	f.assignments[policyID][roleID] = true
}

// GrantFullAccessToRole seeds a policy matching migrations/000027's own
// backward-compatibility default (path pattern "*", every action, effect
// allow) and assigns it to roleID in one call — the fake's equivalent of
// that migration's seed, so a test can grant "this role can reach every
// secret path" in one line without constructing the policy/rule/
// assignment rows by hand.
func (f *FakeSecretPolicyRepository) GrantFullAccessToRole(roleID string) {
	p := f.SeedPolicy(&entity.SecretPolicy{Name: "test-full-access"})
	f.SeedRule(p.ID, &entity.SecretPolicyRule{
		PathPattern: "*",
		Effect:      entity.PolicyEffectAllow,
		Actions: []entity.PolicyAction{
			entity.PolicyActionRead, entity.PolicyActionCreate, entity.PolicyActionUpdate,
			entity.PolicyActionDelete, entity.PolicyActionList, entity.PolicyActionRollback,
		},
	})
	f.AssignRole(p.ID, roleID)
}

func (f *FakeSecretPolicyRepository) Create(_ context.Context, p *entity.SecretPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.policies {
		orgMatch := (existing.OrganizationID == nil) == (p.OrganizationID == nil)
		if orgMatch && existing.OrganizationID != nil && p.OrganizationID != nil {
			orgMatch = *existing.OrganizationID == *p.OrganizationID
		}
		if orgMatch && existing.Name == p.Name {
			return entity.ErrAlreadyExists
		}
	}
	p.ID = util.NewUUID()
	p.CreatedAt, p.UpdatedAt = time.Now(), time.Now()
	f.policies[p.ID] = p
	return nil
}

func (f *FakeSecretPolicyRepository) GetByID(_ context.Context, id string) (*entity.SecretPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.policies[id]
	if !ok {
		return nil, entity.ErrNotFound
	}
	return p, nil
}

func (f *FakeSecretPolicyRepository) List(_ context.Context, organizationID string) ([]*entity.SecretPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.SecretPolicy
	for _, p := range f.policies {
		if p.OrganizationID == nil || *p.OrganizationID == organizationID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *FakeSecretPolicyRepository) Update(_ context.Context, p *entity.SecretPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.policies[p.ID]
	if !ok {
		return entity.ErrNotFound
	}
	existing.Name, existing.Description, existing.UpdatedAt = p.Name, p.Description, time.Now()
	return nil
}

func (f *FakeSecretPolicyRepository) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.policies[id]; !ok {
		return entity.ErrNotFound
	}
	delete(f.policies, id)
	delete(f.rules, id)
	delete(f.assignments, id)
	return nil
}

func (f *FakeSecretPolicyRepository) ReplaceRules(_ context.Context, policyID string, rules []*entity.SecretPolicyRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.policies[policyID]; !ok {
		return entity.ErrNotFound
	}
	out := make([]*entity.SecretPolicyRule, len(rules))
	for i, r := range rules {
		cp := *r
		cp.ID = util.NewUUID()
		cp.PolicyID = policyID
		cp.CreatedAt = time.Now()
		out[i] = &cp
	}
	f.rules[policyID] = out
	return nil
}

func (f *FakeSecretPolicyRepository) ListRules(_ context.Context, policyID string) ([]*entity.SecretPolicyRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rules[policyID], nil
}

func (f *FakeSecretPolicyRepository) AssignToRole(_ context.Context, a *entity.SecretPolicyRoleAssignment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.policies[a.PolicyID]; !ok {
		return entity.ErrNotFound
	}
	if f.assignments[a.PolicyID] == nil {
		f.assignments[a.PolicyID] = map[string]bool{}
	}
	f.assignments[a.PolicyID][a.RoleID] = true
	return nil
}

func (f *FakeSecretPolicyRepository) UnassignFromRole(_ context.Context, policyID, roleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.assignments[policyID][roleID] {
		return entity.ErrNotFound
	}
	delete(f.assignments[policyID], roleID)
	return nil
}

func (f *FakeSecretPolicyRepository) ListAssignedRoleIDs(_ context.Context, policyID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ids []string
	for roleID := range f.assignments[policyID] {
		ids = append(ids, roleID)
	}
	return ids, nil
}

func (f *FakeSecretPolicyRepository) ListRulesForRoles(_ context.Context, organizationID string, roleIDs []string) ([]*entity.SecretPolicyRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	roleSet := make(map[string]bool, len(roleIDs))
	for _, id := range roleIDs {
		roleSet[id] = true
	}

	var out []*entity.SecretPolicyRule
	for policyID, roleAssignments := range f.assignments {
		policy, ok := f.policies[policyID]
		if !ok {
			continue
		}
		if policy.OrganizationID != nil && *policy.OrganizationID != organizationID {
			continue
		}
		assigned := false
		for roleID := range roleAssignments {
			if roleSet[roleID] {
				assigned = true
				break
			}
		}
		if !assigned {
			continue
		}
		out = append(out, f.rules[policyID]...)
	}
	return out, nil
}

// FakeServiceAccountRepository implements repository.ServiceAccountRepository
// over an in-memory map, keyed by ID — the machine-identity mirror of
// FakeUserRepository above, same shape and same conventions (Seed for
// pre-existing rows, Create assigns an ID, GrantRole/RevokeRole/ListRoles
// mirror the user variant exactly since service_account_roles has no
// expires_at column to simulate).
type FakeServiceAccountRepository struct {
	mu    sync.Mutex
	byID  map[string]*entity.ServiceAccount
	roles map[string][]*entity.ServiceAccountRole
}

func NewFakeServiceAccountRepository() *FakeServiceAccountRepository {
	return &FakeServiceAccountRepository{byID: map[string]*entity.ServiceAccount{}, roles: map[string][]*entity.ServiceAccountRole{}}
}

// Seed inserts a service account directly, bypassing Create's ID
// assignment — the natural way a test arranges "given a service account
// that already exists."
func (f *FakeServiceAccountRepository) Seed(sa *entity.ServiceAccount) *entity.ServiceAccount {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sa.ID == "" {
		sa.ID = util.NewUUID()
	}
	if sa.Status == "" {
		sa.Status = entity.ServiceAccountStatusActive
	}
	f.byID[sa.ID] = sa
	return sa
}

// Create mirrors uq_service_accounts_org_name (migrations/000011) so a
// unit test exercising duplicate-name behavior gets the same
// entity.ErrAlreadyExists a real Postgres unique-violation would produce,
// without needing a database.
func (f *FakeServiceAccountRepository) Create(_ context.Context, sa *entity.ServiceAccount) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.byID {
		if existing.OrganizationID == sa.OrganizationID && existing.Name == sa.Name {
			return entity.ErrAlreadyExists
		}
	}
	sa.ID = util.NewUUID()
	sa.CreatedAt, sa.UpdatedAt = time.Now(), time.Now()
	f.byID[sa.ID] = sa
	return nil
}

func (f *FakeServiceAccountRepository) GetByID(_ context.Context, id string) (*entity.ServiceAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sa, ok := f.byID[id]
	if !ok {
		return nil, entity.ErrNotFound
	}
	cp := *sa
	return &cp, nil
}

func (f *FakeServiceAccountRepository) List(_ context.Context, organizationID string, _ *string, _ int) ([]*entity.ServiceAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.ServiceAccount
	for _, sa := range f.byID {
		if sa.OrganizationID == organizationID {
			cp := *sa
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (f *FakeServiceAccountRepository) Update(_ context.Context, sa *entity.ServiceAccount) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byID[sa.ID]; !ok {
		return entity.ErrNotFound
	}
	sa.UpdatedAt = time.Now()
	f.byID[sa.ID] = sa
	return nil
}

func (f *FakeServiceAccountRepository) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byID[id]; !ok {
		return entity.ErrNotFound
	}
	delete(f.byID, id)
	delete(f.roles, id)
	return nil
}

func (f *FakeServiceAccountRepository) TouchLastAuthenticated(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sa, ok := f.byID[id]; ok {
		now := time.Now()
		sa.LastAuthenticatedAt = &now
	}
	return nil
}

func (f *FakeServiceAccountRepository) GrantRole(_ context.Context, g *entity.ServiceAccountRole) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g.AssignedAt = time.Now()
	f.roles[g.ServiceAccountID] = append(f.roles[g.ServiceAccountID], g)
	return nil
}

func (f *FakeServiceAccountRepository) RevokeRole(_ context.Context, serviceAccountID, roleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	grants := f.roles[serviceAccountID]
	for i, g := range grants {
		if g.RoleID == roleID {
			f.roles[serviceAccountID] = append(grants[:i], grants[i+1:]...)
			return nil
		}
	}
	return entity.ErrNotFound
}

func (f *FakeServiceAccountRepository) ListRoles(_ context.Context, serviceAccountID string) ([]*entity.ServiceAccountRole, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roles[serviceAccountID], nil
}

// FakeAPIKeyRepository implements repository.APIKeyRepository over an
// in-memory map, keyed by ID — GetByKeyHash is the one lookup
// service.ServiceAccountService.Authenticate actually depends on, an
// exact map lookup here the same way key_hash's real UNIQUE index makes
// it an exact indexed match in Postgres.
type FakeAPIKeyRepository struct {
	mu   sync.Mutex
	byID map[string]*entity.APIKey
}

func NewFakeAPIKeyRepository() *FakeAPIKeyRepository {
	return &FakeAPIKeyRepository{byID: map[string]*entity.APIKey{}}
}

// Seed inserts a key directly, bypassing Create's ID assignment.
func (f *FakeAPIKeyRepository) Seed(k *entity.APIKey) *entity.APIKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k.ID == "" {
		k.ID = util.NewUUID()
	}
	if k.Status == "" {
		k.Status = entity.APIKeyStatusActive
	}
	f.byID[k.ID] = k
	return k
}

func (f *FakeAPIKeyRepository) Create(_ context.Context, k *entity.APIKey) error {
	if !k.HasSingleOwner() {
		return entity.ErrOwnerConflict
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.byID {
		if existing.KeyHash == k.KeyHash {
			return entity.ErrAlreadyExists
		}
	}
	k.ID = util.NewUUID()
	k.CreatedAt = time.Now()
	f.byID[k.ID] = k
	return nil
}

func (f *FakeAPIKeyRepository) GetByID(_ context.Context, id string) (*entity.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.byID[id]
	if !ok {
		return nil, entity.ErrNotFound
	}
	cp := *k
	return &cp, nil
}

func (f *FakeAPIKeyRepository) GetByKeyHash(_ context.Context, keyHash string) (*entity.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.byID {
		if k.KeyHash == keyHash {
			cp := *k
			return &cp, nil
		}
	}
	return nil, entity.ErrNotFound
}

func (f *FakeAPIKeyRepository) List(_ context.Context, _ string, filter repository.ApiKeyFilter) ([]*entity.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.APIKey
	for _, k := range f.byID {
		if filter.OwnerUserID != nil && (k.OwnerUserID == nil || *k.OwnerUserID != *filter.OwnerUserID) {
			continue
		}
		if filter.OwnerServiceAccountID != nil && (k.OwnerServiceAccountID == nil || *k.OwnerServiceAccountID != *filter.OwnerServiceAccountID) {
			continue
		}
		if filter.Status != nil && k.Status != *filter.Status {
			continue
		}
		cp := *k
		out = append(out, &cp)
	}
	return out, nil
}

func (f *FakeAPIKeyRepository) Revoke(_ context.Context, id string, reason *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.byID[id]
	if !ok {
		return entity.ErrNotFound
	}
	if k.Status != entity.APIKeyStatusActive {
		return entity.ErrNotFound
	}
	now := time.Now()
	k.Status = entity.APIKeyStatusRevoked
	k.RevokedAt = &now
	k.RevokedReason = reason
	return nil
}

func (f *FakeAPIKeyRepository) TouchLastUsed(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k, ok := f.byID[id]; ok {
		now := time.Now()
		k.LastUsedAt = &now
	}
	return nil
}

func (f *FakeAPIKeyRepository) AddPermission(_ context.Context, _ *entity.APIKeyPermission) error {
	return nil
}

func (f *FakeAPIKeyRepository) RemovePermission(_ context.Context, _, _ string) error {
	return nil
}

func (f *FakeAPIKeyRepository) ListPermissions(_ context.Context, _ string) ([]*entity.Permission, error) {
	return nil, nil
}

// FakeLeaseRepository implements repository.LeaseRepository over an
// in-memory map, keyed by ID — Renew/Revoke both mirror
// postgres.leaseRepository's own `WHERE status = 'active'` guards exactly
// (Renew fails entity.ErrNotFound on a non-active row via
// checkRowsAffected's own "zero rows affected" convention; Revoke returns
// transitioned=false, nil — never an error — for the identical case, see
// that method's own doc comment) so a unit test exercising "renew an
// already-revoked lease" or "revoke twice" against this fake proves the
// same behavior test/integration's real-Postgres tests separately prove
// against the genuine schema.
type FakeLeaseRepository struct {
	mu   sync.Mutex
	byID map[string]*entity.Lease
	// FailNextCreate, if non-nil, is returned by the next Create call
	// instead of succeeding, then reset to nil — the same fault-injection
	// convention as FakeAuditLogRepository.FailNext, for exercising
	// LeaseService.Create's own compensating-credential-revocation path
	// (see that method's own doc comment) without a real database to
	// actually break.
	FailNextCreate error
}

func NewFakeLeaseRepository() *FakeLeaseRepository {
	return &FakeLeaseRepository{byID: map[string]*entity.Lease{}}
}

// Seed inserts a lease directly, bypassing Create's ID/CreatedAt
// assignment — the natural way a test arranges "given a lease already in
// this state" (e.g. one already expired or already revoked).
func (f *FakeLeaseRepository) Seed(l *entity.Lease) *entity.Lease {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l.ID == "" {
		l.ID = util.NewUUID()
	}
	if l.Status == "" {
		l.Status = entity.LeaseStatusActive
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now()
	}
	f.byID[l.ID] = l
	return l
}

func (f *FakeLeaseRepository) Create(_ context.Context, l *entity.Lease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailNextCreate != nil {
		err := f.FailNextCreate
		f.FailNextCreate = nil
		return err
	}
	l.ID = util.NewUUID()
	l.CreatedAt = time.Now()
	f.byID[l.ID] = l
	return nil
}

func (f *FakeLeaseRepository) GetByID(_ context.Context, id string) (*entity.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.byID[id]
	if !ok {
		return nil, entity.ErrNotFound
	}
	cp := *l
	return &cp, nil
}

func (f *FakeLeaseRepository) List(_ context.Context, organizationID string, filter repository.LeaseFilter) ([]*entity.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.Lease
	for _, l := range f.byID {
		if l.OrganizationID != organizationID {
			continue
		}
		if filter.OwnerIdentityType != nil && l.OwnerIdentityType != *filter.OwnerIdentityType {
			continue
		}
		if filter.OwnerIdentityID != nil && l.OwnerIdentityID != *filter.OwnerIdentityID {
			continue
		}
		if filter.Status != nil && l.Status != *filter.Status {
			continue
		}
		cp := *l
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, nil
}

func (f *FakeLeaseRepository) Renew(_ context.Context, id string, newTTL time.Duration, newExpiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.byID[id]
	if !ok || l.Status != entity.LeaseStatusActive {
		return entity.ErrNotFound
	}
	l.TTL, l.ExpiresAt = newTTL, newExpiresAt
	return nil
}

func (f *FakeLeaseRepository) Revoke(_ context.Context, id string, reason *string, at time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.byID[id]
	if !ok || l.Status != entity.LeaseStatusActive {
		return false, nil
	}
	l.Status = entity.LeaseStatusRevoked
	l.RevokedAt, l.RevokedReason = &at, reason
	return true, nil
}

func (f *FakeLeaseRepository) ExpireOverdue(_ context.Context, at time.Time) ([]*entity.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*entity.Lease
	for _, l := range f.byID {
		if l.Status == entity.LeaseStatusActive && !at.Before(l.ExpiresAt) {
			l.Status = entity.LeaseStatusExpired
			cp := *l
			out = append(out, &cp)
		}
	}
	return out, nil
}
