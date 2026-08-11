package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/acme/auth-service/internal/secrets"
)

// keyMetadataStore implements secrets.KeyMetadataStore (migrations/000026)
// — persisting internal/secrets.KeyManager's own bookkeeping of which key
// identifiers exist and their lifecycle state, never key material. This
// file is allowed to depend on internal/secrets (it exists specifically to
// persist that package's types); the dependency never runs the other way —
// see KeyMetadataStore's own doc comment.
type keyMetadataStore struct{ db *sql.DB }

// NewKeyMetadataStore constructs a secrets.KeyMetadataStore backed by the
// encryption_keys table.
func NewKeyMetadataStore(db *sql.DB) secrets.KeyMetadataStore {
	return &keyMetadataStore{db: db}
}

const keyMetadataColumns = `key_id, algorithm, state, created_at, activated_at, retired_at, disabled_at`

func scanKeyMetadata(row interface{ Scan(dest ...any) error }) (secrets.KeyMetadata, error) {
	var m secrets.KeyMetadata
	var activatedAt, retiredAt, disabledAt sql.NullTime
	err := row.Scan(&m.KeyID, &m.Algorithm, &m.State, &m.CreatedAt, &activatedAt, &retiredAt, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		return secrets.KeyMetadata{}, secrets.ErrKeyNotFound
	}
	if err != nil {
		return secrets.KeyMetadata{}, err
	}
	m.ActivatedAt = nullTime(activatedAt)
	m.RetiredAt = nullTime(retiredAt)
	m.DisabledAt = nullTime(disabledAt)
	return m, nil
}

func (s *keyMetadataStore) Get(ctx context.Context, keyID string) (secrets.KeyMetadata, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+keyMetadataColumns+` FROM encryption_keys WHERE key_id = $1`, keyID)
	return scanKeyMetadata(row)
}

func (s *keyMetadataStore) GetActive(ctx context.Context) (secrets.KeyMetadata, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+keyMetadataColumns+` FROM encryption_keys WHERE state = 'active'`)
	meta, err := scanKeyMetadata(row)
	if errors.Is(err, secrets.ErrKeyNotFound) {
		return secrets.KeyMetadata{}, secrets.ErrNoActiveKey
	}
	return meta, err
}

func (s *keyMetadataStore) List(ctx context.Context) ([]secrets.KeyMetadata, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+keyMetadataColumns+` FROM encryption_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []secrets.KeyMetadata
	for rows.Next() {
		m, err := scanKeyMetadata(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Bootstrap inserts meta only if encryption_keys is currently empty —
// KeyManager.bootstrapFromProvider has already made that same check
// against its own view, but this store re-verifies it inside the same
// transaction as the insert so two processes racing to bootstrap for the
// first time (e.g. two replicas starting up simultaneously) cannot both
// succeed: the second one's INSERT ... SELECT WHERE NOT EXISTS simply
// inserts zero rows, and it re-reads whatever the winner actually wrote.
func (s *keyMetadataStore) Bootstrap(ctx context.Context, meta secrets.KeyMetadata) (secrets.KeyMetadata, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return secrets.KeyMetadata{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after a successful Commit

	res, err := tx.ExecContext(ctx, `
		INSERT INTO encryption_keys (key_id, algorithm, state, created_at, activated_at)
		SELECT $1, $2, 'active', $3, $3
		WHERE NOT EXISTS (SELECT 1 FROM encryption_keys)`,
		meta.KeyID, meta.Algorithm, meta.CreatedAt,
	)
	if err != nil {
		return secrets.KeyMetadata{}, false, translateKeyError(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return secrets.KeyMetadata{}, false, err
	}
	if n == 0 {
		// Someone else already bootstrapped (or the store was never
		// actually empty) — read back whatever is really there instead of
		// claiming success for an insert that did not happen.
		if err := tx.Commit(); err != nil {
			return secrets.KeyMetadata{}, false, err
		}
		existing, err := s.GetActive(ctx)
		if err != nil {
			return secrets.KeyMetadata{}, false, err
		}
		return existing, false, nil
	}
	if err := tx.Commit(); err != nil {
		return secrets.KeyMetadata{}, false, err
	}
	return meta, true, nil
}

// ActivateNewKey retires whichever key is currently active and activates
// newKeyID in one transaction — see secrets.KeyMetadataStore.ActivateNewKey's
// doc comment for why that atomicity matters (the "partially completed
// rotation" safeguard the objective calls for).
func (s *keyMetadataStore) ActivateNewKey(ctx context.Context, newKeyID, algorithm string, now time.Time) (secrets.KeyMetadata, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return secrets.KeyMetadata{}, err
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after a successful Commit

	if _, err := tx.ExecContext(ctx,
		`UPDATE encryption_keys SET state = 'retiring' WHERE state = 'active'`,
	); err != nil {
		return secrets.KeyMetadata{}, err
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO encryption_keys (key_id, algorithm, state, created_at, activated_at)
		VALUES ($1, $2, 'active', $3, $3)`,
		newKeyID, algorithm, now,
	); err != nil {
		return secrets.KeyMetadata{}, translateKeyError(err)
	}

	if err := tx.Commit(); err != nil {
		return secrets.KeyMetadata{}, err
	}
	return secrets.KeyMetadata{KeyID: newKeyID, Algorithm: algorithm, State: secrets.KeyStateActive, CreatedAt: now, ActivatedAt: &now}, nil
}

func (s *keyMetadataStore) UpdateState(ctx context.Context, keyID string, newState secrets.KeyState, at time.Time) error {
	var query string
	switch newState {
	case secrets.KeyStateActive:
		query = `UPDATE encryption_keys SET state = $2, activated_at = $3 WHERE key_id = $1`
	case secrets.KeyStateRetired:
		query = `UPDATE encryption_keys SET state = $2, retired_at = $3 WHERE key_id = $1`
	case secrets.KeyStateDisabled:
		query = `UPDATE encryption_keys SET state = $2, disabled_at = $3 WHERE key_id = $1`
	default:
		query = `UPDATE encryption_keys SET state = $2 WHERE key_id = $1`
	}
	res, err := s.db.ExecContext(ctx, query, keyID, string(newState), at)
	return checkRowsAffectedKeyRepo(res, err)
}

func checkRowsAffectedKeyRepo(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return secrets.ErrKeyNotFound
	}
	return nil
}

// translateKeyError maps encryption_keys.key_id's PRIMARY KEY collision to
// secrets.ErrKeyAlreadyExists — the KeyMetadataStore-specific equivalent
// of errors.go's translateError, kept separate because this file must
// never return an internal/entity error type (see KeyMetadataStore's own
// doc comment on why internal/secrets, and therefore anything implementing
// its interfaces, stays independent of internal/entity).
func translateKeyError(err error) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == pgUniqueViolation {
		return fmt.Errorf("%w: %w", secrets.ErrKeyAlreadyExists, err)
	}
	return err
}
