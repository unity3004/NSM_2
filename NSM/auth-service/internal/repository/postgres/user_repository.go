package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

type userRepository struct {
	db dbtx
}

// NewUserRepository returns a repository.UserRepository backed by
// PostgreSQL. It takes the package's dbtx interface, not a concrete
// *sql.DB, so a caller orchestrating a multi-repository transaction (see
// UserService.Register and database.WithTx) can construct a
// transaction-scoped instance via NewUserRepository(tx) — *sql.Tx
// satisfies dbtx exactly like *sql.DB does, so cmd/server/main.go's
// existing NewUserRepository(db) call is unaffected.
func NewUserRepository(db dbtx) repository.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, u *entity.User) error {
	const q = `
		INSERT INTO users (organization_id, email, username, password_hash, password_algo, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at`
	err := r.db.QueryRowContext(ctx, q,
		u.OrganizationID, u.Email, toNullString(u.Username), toNullString(u.PasswordHash), toNullString(u.PasswordAlgo), u.Status,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	return translateError(err)
}

func (r *userRepository) scanUser(row interface {
	Scan(dest ...any) error
}) (*entity.User, error) {
	var u entity.User
	var username, passwordHash, passwordAlgo sql.NullString
	var emailVerifiedAt, lockedUntil, lastLoginAt, deletedAt sql.NullTime
	err := row.Scan(
		&u.ID, &u.OrganizationID, &u.Email, &username, &passwordHash, &passwordAlgo,
		&u.Status, &u.MFAEnabled, &emailVerifiedAt, &u.FailedLoginAttempts, &lockedUntil,
		&lastLoginAt, &u.CreatedAt, &u.UpdatedAt, &deletedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Username = nullString(username)
	u.PasswordHash = nullString(passwordHash)
	u.PasswordAlgo = nullString(passwordAlgo)
	u.EmailVerifiedAt = nullTime(emailVerifiedAt)
	u.LockedUntil = nullTime(lockedUntil)
	u.LastLoginAt = nullTime(lastLoginAt)
	u.DeletedAt = nullTime(deletedAt)
	return &u, nil
}

const userColumns = `id, organization_id, email, username, password_hash, password_algo,
	status, mfa_enabled, email_verified_at, failed_login_attempts, locked_until,
	last_login_at, created_at, updated_at, deleted_at`

func (r *userRepository) GetByID(ctx context.Context, id string) (*entity.User, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 AND deleted_at IS NULL`, id)
	return r.scanUser(row)
}

func (r *userRepository) GetByEmail(ctx context.Context, organizationID, email string) (*entity.User, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE organization_id = $1 AND email = $2 AND deleted_at IS NULL`,
		organizationID, email)
	return r.scanUser(row)
}

func (r *userRepository) List(ctx context.Context, organizationID string, f repository.UserFilter) ([]*entity.User, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	// A cursor here is the last row's (created_at, id) pair, base64-encoded
	// by internal/util — decoding it is the service layer's job, not the
	// repository's; List just accepts the resulting `after` values.
	query := `SELECT ` + userColumns + ` FROM users WHERE organization_id = $1 AND deleted_at IS NULL`
	args := []any{organizationID}
	if f.Status != nil {
		args = append(args, *f.Status)
		query += ` AND status = $` + strconv.Itoa(len(args))
	}
	if f.Email != nil {
		args = append(args, *f.Email)
		query += ` AND lower(email) = lower($` + strconv.Itoa(len(args)) + `)`
	}
	args = append(args, limit)
	query += ` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*entity.User
	for rows.Next() {
		u, err := r.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *userRepository) Update(ctx context.Context, u *entity.User) error {
	const q = `
		UPDATE users SET username = $1, status = $2, mfa_enabled = $3, updated_at = now()
		WHERE id = $4 AND deleted_at IS NULL
		RETURNING updated_at`
	err := r.db.QueryRowContext(ctx, q, toNullString(u.Username), u.Status, u.MFAEnabled, u.ID).Scan(&u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return entity.ErrNotFound
	}
	return err
}

func (r *userRepository) SoftDelete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	return checkRowsAffected(res, err)
}

func (r *userRepository) IncrementFailedLoginAttempts(ctx context.Context, id string) (int, error) {
	var attempts int
	err := r.db.QueryRowContext(ctx,
		`UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1 RETURNING failed_login_attempts`,
		id,
	).Scan(&attempts)
	return attempts, err
}

func (r *userRepository) ResetFailedLoginAttempts(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1`, id)
	return err
}

func (r *userRepository) Lock(ctx context.Context, id string, until time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE users SET locked_until = $1 WHERE id = $2`, until, id)
	return err
}

func (r *userRepository) GrantRole(ctx context.Context, grant *entity.UserRole) error {
	const q = `
		INSERT INTO user_roles (user_id, role_id, assigned_by, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING assigned_at`
	err := r.db.QueryRowContext(ctx, q, grant.UserID, grant.RoleID, toNullString(grant.AssignedBy), toNullTime(grant.ExpiresAt)).
		Scan(&grant.AssignedAt)
	return translateError(err)
}

func (r *userRepository) RevokeRole(ctx context.Context, userID, roleID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
	return checkRowsAffected(res, err)
}

func (r *userRepository) ListRoles(ctx context.Context, userID string) ([]*entity.UserRole, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT user_id, role_id, assigned_by, assigned_at, expires_at FROM user_roles
		 WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now())`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []*entity.UserRole
	for rows.Next() {
		var g entity.UserRole
		var assignedBy sql.NullString
		var expiresAt sql.NullTime
		if err := rows.Scan(&g.UserID, &g.RoleID, &assignedBy, &g.AssignedAt, &expiresAt); err != nil {
			return nil, err
		}
		g.AssignedBy = nullString(assignedBy)
		g.ExpiresAt = nullTime(expiresAt)
		grants = append(grants, &g)
	}
	return grants, rows.Err()
}
