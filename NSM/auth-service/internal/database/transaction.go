package database

import (
	"context"
	"database/sql"
	"fmt"
)

// WithTx runs fn inside a transaction, committing on success and rolling
// back on any error (including a panic, which it re-raises after
// rolling back). It exists so a use case that touches more than one
// repository — creating an entity.APIKey and its entity.APIKeyPermission
// rows together, for instance — can do so atomically without every
// repository method needing a transaction-aware variant of itself: pass
// the *sql.Tx this hands you to the same repository constructors used
// outside a transaction (they only require the dbtx interface).
func WithTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("database: begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback() //nolint:errcheck
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("database: rollback failed: %v (original error: %w)", rbErr, err)
		}
		return err
	}
	return tx.Commit()
}
