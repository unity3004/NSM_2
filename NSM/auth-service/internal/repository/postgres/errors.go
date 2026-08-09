// Package postgres implements the ports declared in internal/repository
// against a real PostgreSQL database, using database/sql directly — no ORM.
// Clean Architecture's whole payoff shows up at this boundary: every file
// here could be deleted and replaced with a different storage engine
// without internal/service ever noticing, because service only ever holds
// a repository.UserRepository (an interface), never a *postgres.userRepository.
package postgres

import (
	"errors"

	"github.com/acme/auth-service/internal/entity"
	"github.com/lib/pq"
)

// pgUniqueViolation is Postgres's SQLSTATE for a unique-constraint failure
// (e.g. uq_users_org_email, uq_organizations_slug). Translating it here,
// once, means no repository method above this file ever has to know a
// Postgres error code.
const pgUniqueViolation = "23505"

func translateError(err error) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == pgUniqueViolation {
		return entity.ErrAlreadyExists
	}
	return err
}
