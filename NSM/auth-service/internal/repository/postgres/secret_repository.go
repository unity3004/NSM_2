package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// secretRepository takes a concrete *sql.DB, not the package's dbtx
// interface, for the same reason refreshTokenRepository does: CreateVersion
// needs BeginTx, which dbtx doesn't expose. See CreateVersion's own comment
// for why that transaction exists.
type secretRepository struct{ db *sql.DB }

func NewSecretRepository(db *sql.DB) repository.SecretRepository {
	return &secretRepository{db: db}
}

const secretColumns = `id, organization_id, path, current_version, created_by, created_at, updated_at, deleted_at`

func scanSecret(row interface{ Scan(dest ...any) error }) (*entity.Secret, error) {
	var s entity.Secret
	var deletedAt sql.NullTime
	err := row.Scan(&s.ID, &s.OrganizationID, &s.Path, &s.CurrentVersion, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.DeletedAt = nullTime(deletedAt)
	return &s, nil
}

func (r *secretRepository) Create(ctx context.Context, s *entity.Secret) error {
	return r.createSecret(ctx, r.db, s)
}

// createSecret runs the actual INSERT against whatever dbtx it's given
// (r.db for the standalone Create path, a *sql.Tx for
// CreateWithFirstVersion's atomic path) — the one place both callers'
// INSERT logic lives, so they can never drift apart.
//
// A caller-supplied s.ID (Sprint 3 Phase 3's SecretService generates one
// up front, before the row exists, so it can bind AES-GCM's additional
// authenticated data to the secret's own identity during encryption — see
// secrets.EncryptContext's doc comment) is used verbatim instead of
// letting the database's own DEFAULT gen_random_uuid() generate one;
// every existing caller that leaves s.ID empty (Phase 1's own tests, and
// anything else that doesn't need the ID before Create returns) gets a
// UUID generated here in Go instead, which is behaviorally identical — a
// valid, randomly generated v4 UUID either way.
func (r *secretRepository) createSecret(ctx context.Context, db dbtx, s *entity.Secret) error {
	if s.ID == "" {
		s.ID = util.NewUUID()
	}
	const q = `
		INSERT INTO secrets (id, organization_id, path, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, current_version, created_at, updated_at`
	err := db.QueryRowContext(ctx, q, s.ID, s.OrganizationID, s.Path, s.CreatedBy).
		Scan(&s.ID, &s.CurrentVersion, &s.CreatedAt, &s.UpdatedAt)
	return translateError(err)
}

func (r *secretRepository) GetByID(ctx context.Context, id string) (*entity.Secret, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+secretColumns+` FROM secrets WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanSecret(row)
}

func (r *secretRepository) GetByPath(ctx context.Context, organizationID, path string) (*entity.Secret, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+secretColumns+` FROM secrets WHERE organization_id = $1 AND path = $2 AND deleted_at IS NULL`,
		organizationID, path)
	return scanSecret(row)
}

func (r *secretRepository) List(ctx context.Context, organizationID string, f repository.SecretFilter) ([]*entity.Secret, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+secretColumns+` FROM secrets WHERE organization_id = $1 AND deleted_at IS NULL
		 ORDER BY path ASC LIMIT $2`,
		organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []*entity.Secret
	for rows.Next() {
		s, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, s)
	}
	return secrets, rows.Err()
}

func (r *secretRepository) SoftDelete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE secrets SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	return checkRowsAffected(res, err)
}

// CreateWithFirstVersion creates s and v (fixed to version 1) inside one
// transaction. No row-lock is needed the way CreateVersion needs
// `SELECT ... FOR UPDATE`: s is inserted for the first time in this same
// transaction, so — thanks to Postgres's MVCC — no other transaction can
// see it, let alone race to create a version for it, until this one
// commits.
func (r *secretRepository) CreateWithFirstVersion(ctx context.Context, s *entity.Secret, v *entity.SecretVersion) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after a successful Commit

	if err := r.createSecret(ctx, tx, s); err != nil {
		return err
	}

	v.SecretID = s.ID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO secret_versions (secret_id, version, ciphertext, nonce, auth_tag, algorithm, wrapped_dek, key_id, key_version, created_by)
		VALUES ($1, 1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`,
		v.SecretID, v.Ciphertext, v.Nonce, v.AuthTag, v.Algorithm, v.WrappedDEK, v.KeyID,
		toNullString(v.KeyVersion), v.CreatedBy,
	).Scan(&v.ID, &v.CreatedAt)
	if err != nil {
		return translateError(err)
	}
	v.Version = 1

	res, err := tx.ExecContext(ctx,
		`UPDATE secrets SET current_version = 1, updated_at = now() WHERE id = $1`, s.ID)
	if err := checkRowsAffected(res, err); err != nil {
		return err
	}
	s.CurrentVersion = 1

	return tx.Commit()
}

const secretVersionColumns = `id, secret_id, version, ciphertext, nonce, auth_tag, algorithm, wrapped_dek, key_id, key_version, created_by, created_at, deleted_at`

func scanSecretVersion(row interface{ Scan(dest ...any) error }) (*entity.SecretVersion, error) {
	var v entity.SecretVersion
	var keyVersion sql.NullString
	var deletedAt sql.NullTime
	err := row.Scan(&v.ID, &v.SecretID, &v.Version, &v.Ciphertext, &v.Nonce, &v.AuthTag, &v.Algorithm,
		&v.WrappedDEK, &v.KeyID, &keyVersion, &v.CreatedBy, &v.CreatedAt, &deletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.KeyVersion = nullString(keyVersion)
	v.DeletedAt = nullTime(deletedAt)
	return &v, nil
}

// CountVersionsByKeyID is a deliberately unfiltered, cross-organization
// query — see the interface's own doc comment for why that scope is
// correct here, unlike every other method on this repository.
func (r *secretRepository) CountVersionsByKeyID(ctx context.Context, keyID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM secret_versions WHERE key_id = $1`, keyID,
	).Scan(&count)
	return count, err
}

// CreateVersion locks the parent secrets row, computes the next version
// number from it, inserts the new secret_versions row and advances
// secrets.current_version — all inside one transaction. Equivalent to
// CreateVersionIfCurrent with expectedCurrentVersion 0; see that method for
// the full doc comment and both methods' shared implementation.
func (r *secretRepository) CreateVersion(ctx context.Context, v *entity.SecretVersion) error {
	return r.createVersion(ctx, v, 0)
}

// CreateVersionIfCurrent additionally enforces optimistic concurrency —
// see the interface's own doc comment (internal/repository/secret.go) for
// the contract; expectedCurrentVersion <= 0 means "no expectation".
//
// The `SELECT ... FOR UPDATE` is what actually prevents duplicate version
// numbers under concurrency, and is also what makes the optimistic
// concurrency check race-free: two simultaneous calls for the same
// secret_id serialize on that row lock, so the second call always reads
// the first call's already-committed current_version — never a stale
// value — before deciding whether to proceed or reject with
// entity.ErrVersionConflict. uq_secret_versions_secret_version
// (migrations/000024) remains the backstop behind the duplicate-version
// half of that guarantee, independent of this check.
//
// Like refreshTokenRepository.Rotate, this only provides its atomicity
// guarantee via BeginTx because secretRepository's db field is a concrete
// *sql.DB — see the type's own comment.
func (r *secretRepository) CreateVersionIfCurrent(ctx context.Context, v *entity.SecretVersion, expectedCurrentVersion int) error {
	return r.createVersion(ctx, v, expectedCurrentVersion)
}

func (r *secretRepository) createVersion(ctx context.Context, v *entity.SecretVersion, expectedCurrentVersion int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after a successful Commit

	var currentVersion int
	err = tx.QueryRowContext(ctx,
		`SELECT current_version FROM secrets WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
		v.SecretID,
	).Scan(&currentVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.ErrNotFound
	}
	if err != nil {
		return err
	}
	if expectedCurrentVersion > 0 && currentVersion != expectedCurrentVersion {
		return entity.ErrVersionConflict
	}
	nextVersion := currentVersion + 1

	err = tx.QueryRowContext(ctx, `
		INSERT INTO secret_versions (secret_id, version, ciphertext, nonce, auth_tag, algorithm, wrapped_dek, key_id, key_version, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at`,
		v.SecretID, nextVersion, v.Ciphertext, v.Nonce, v.AuthTag, v.Algorithm, v.WrappedDEK, v.KeyID,
		toNullString(v.KeyVersion), v.CreatedBy,
	).Scan(&v.ID, &v.CreatedAt)
	if err != nil {
		return translateError(err)
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE secrets SET current_version = $1, updated_at = now() WHERE id = $2`,
		nextVersion, v.SecretID)
	if err := checkRowsAffected(res, err); err != nil {
		return err
	}

	v.Version = nextVersion
	return tx.Commit()
}

func (r *secretRepository) GetVersion(ctx context.Context, secretID string, version int) (*entity.SecretVersion, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+secretVersionColumns+` FROM secret_versions WHERE secret_id = $1 AND version = $2 AND deleted_at IS NULL`,
		secretID, version)
	return scanSecretVersion(row)
}

func (r *secretRepository) GetCurrentVersion(ctx context.Context, secretID string) (*entity.SecretVersion, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+secretVersionColumns+` FROM secret_versions
		WHERE secret_id = $1 AND deleted_at IS NULL
		  AND version = (SELECT current_version FROM secrets WHERE id = $1)`,
		secretID)
	return scanSecretVersion(row)
}

func (r *secretRepository) ListVersions(ctx context.Context, secretID string) ([]*entity.SecretVersion, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+secretVersionColumns+` FROM secret_versions WHERE secret_id = $1 AND deleted_at IS NULL ORDER BY version DESC`,
		secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []*entity.SecretVersion
	for rows.Next() {
		v, err := scanSecretVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

func (r *secretRepository) SoftDeleteVersion(ctx context.Context, secretID string, version int) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE secret_versions SET deleted_at = now() WHERE secret_id = $1 AND version = $2 AND deleted_at IS NULL`,
		secretID, version)
	return checkRowsAffected(res, err)
}

// ListVersionsByKeyID deliberately does not filter deleted_at IS NULL —
// see CountVersionsByKeyID's own doc comment for why soft-deleted
// versions still need re-encryption too (their ciphertext is still
// present and still needs a usable key). Ordered by id for a stable,
// repeatable scan order across repeated calls as rows are migrated out
// from under it — see the interface's own doc comment for why that's
// what makes an interrupted migration resumable with no separate cursor.
func (r *secretRepository) ListVersionsByKeyID(ctx context.Context, keyID string, limit int) ([]*entity.SecretVersion, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+secretVersionColumns+` FROM secret_versions WHERE key_id = $1 ORDER BY id LIMIT $2`,
		keyID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []*entity.SecretVersion
	for rows.Next() {
		v, err := scanSecretVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// ReEncryptVersion is a single UPDATE statement — already atomic on its
// own (Postgres autocommits one statement), so no explicit
// BeginTx/Commit is needed here the way CreateVersion needs one to span
// its row-lock-then-insert-then-update sequence. This is deliberate:
// the objective's own "a database transaction should protect each
// individual record update... do not hold one giant transaction across
// the entire migration" requirement is satisfied by every record's
// update being its own short, independent statement, not by wrapping
// this method in a transaction of its own.
func (r *secretRepository) ReEncryptVersion(ctx context.Context, versionID string, v repository.ReEncryptedEnvelope, expectedKeyID string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE secret_versions
		SET ciphertext = $1, nonce = $2, auth_tag = $3, wrapped_dek = $4, key_id = $5, algorithm = $6
		WHERE id = $7 AND key_id = $8`,
		v.Ciphertext, v.Nonce, v.AuthTag, v.WrappedDEK, v.KeyID, v.Algorithm, versionID, expectedKeyID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
