package postgres

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// placeholder builds a "$N"-style fragment for hand-assembled dynamic
// filter clauses (see login_history_repository.go's List). It exists so
// every filter-building call site reads as "append this clause, at this
// position" instead of repeating strconv.Itoa noise.
func placeholder(prefix string, n int) string {
	return prefix + strconv.Itoa(n)
}

// dbtx is satisfied by both *sql.DB and *sql.Tx. Every repository method
// below takes one instead of a concrete type, so internal/database's
// WithTx helper can hand a *sql.Tx to the same code paths a plain query
// uses — a repository never needs a second, transaction-flavored copy of
// itself.
type dbtx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// nullString/toNullString convert between the nullable *string used on
// entities and database/sql's sql.NullString, which is the only
// unambiguous way to scan a NULL column into a pointer field.
func nullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func toNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func nullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

func toNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// checkRowsAffected turns "the UPDATE/DELETE matched zero rows" into
// entity.ErrNotFound, so every mutating repository method reports a missing
// row the same way instead of silently succeeding on a no-op.
func checkRowsAffected(res sql.Result, err error) error {
	if err != nil {
		return translateError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return entity.ErrNotFound
	}
	return nil
}
