package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
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
	const q = `
		INSERT INTO secrets (organization_id, path, created_by)
		VALUES ($1, $2, $3)
		RETURNING id, current_version, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, q, s.OrganizationID, s.Path, s.CreatedBy).
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

// CreateVersion locks the parent secrets row, computes the next version
// number from it, inserts the new secret_versions row and advances
// secrets.current_version — all inside one transaction.
//
// The `SELECT ... FOR UPDATE` is what actually prevents duplicate version
// numbers under concurrency: two simultaneous CreateVersion calls for the
// same secret_id serialize on that row lock, so the second call always
// computes its next-version number from the first call's already-committed
// current_version, never from a stale read. uq_secret_versions_secret_version
// (migrations/000024) is the backstop behind that — it makes a duplicate
// version number a constraint violation even if some future caller ever
// reaches this table without going through this lock (e.g. a bug, or a
// second write path added later), rather than silent data corruption.
//
// Like refreshTokenRepository.Rotate, this only provides its atomicity
// guarantee via BeginTx because secretRepository's db field is a concrete
// *sql.DB — see the type's own comment.
func (r *secretRepository) CreateVersion(ctx context.Context, v *entity.SecretVersion) error {
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
