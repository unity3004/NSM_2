// Package database owns the connection to PostgreSQL and the primitives
// (pool configuration, transactions) every internal/repository/postgres
// implementation is built on top of. It has no idea what a User or a
// Session is — that separation is what lets internal/repository/postgres
// stay focused on one table's SQL per file instead of also managing
// connection lifecycle.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // registers the "postgres" driver with database/sql

	"github.com/acme/auth-service/internal/config"
)

// NewPostgresPool opens a connection pool and verifies it can actually
// reach the database before returning — a misconfigured DSN should fail
// at startup, not on the first request. Pool sizing comes from cfg
// (internal/config), not constants in this file: what a conservative
// default is for a single-replica local dev stack and what it is for
// twenty production replicas sharing one Postgres max_connections budget
// are two different numbers, and only the deployment knows which applies —
// see README.md's "why not hardcode configuration."
func NewPostgresPool(ctx context.Context, cfg config.DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("database: open: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database: ping: %w", err)
	}
	return db, nil
}
