package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

type auditLogRepository struct {
	db dbtx
}

// NewAuditLogRepository returns a repository.AuditLogRepository backed by
// PostgreSQL. Append relies on pg_advisory_xact_lock to serialize
// concurrent writers for the same organization — a lock scoped to the
// current transaction, released automatically on commit or rollback. That
// only does its job when db is a transaction (*sql.Tx satisfies dbtx
// exactly like *sql.DB does): a bare *sql.DB runs each statement in its
// own implicit, immediately-committed transaction, so the lock would be
// acquired and released before the next statement ever saw it. Every
// current caller constructs this via a transaction (see
// UserService.Register / database.WithTx) — constructing it directly
// against a plain *sql.DB and calling Append outside a transaction would
// silently lose the concurrency guarantee this file exists to provide.
func NewAuditLogRepository(db dbtx) repository.AuditLogRepository {
	return &auditLogRepository{db: db}
}

// Append computes the next RecordHash from the chain's current tail and
// inserts one immutable row. The hash covers PrevHash plus every field
// that describes the event — actor, action, resource, result, IP, and a
// deterministic JSON encoding of Metadata (Go's encoding/json sorts map
// keys, so the same logical metadata always serializes identically) — so
// altering any field on any historical row, or reordering/deleting rows,
// breaks the chain from that point forward in a way a verifier can detect
// without needing anything beyond the rows themselves.
//
// Metadata must never contain a plaintext password, password hash, secret
// value, or key material. Every call site already hand-picks safe keys by
// convention (see UserService.Register) — Append also applies
// entity.SanitizeAuditMetadata itself (Sprint 4 Task 3), the one place
// every audit write in this codebase passes through regardless of which
// service produced it, so that discipline holds even for a future call
// site that forgets it. The redacted metadata, not the original, is what
// gets hashed into the chain (recordHash below) and what's actually
// stored — an auditor reading the row back sees exactly what was hashed,
// never a discrepancy between the two.
func (r *auditLogRepository) Append(ctx context.Context, e *entity.AuditLogEntry) error {
	e.Metadata = entity.SanitizeAuditMetadata(e.Metadata)
	orgKey := ""
	if e.OrganizationID != nil {
		orgKey = *e.OrganizationID
	}
	// hashtext(text) returns a 32-bit int; pg_advisory_xact_lock wants a
	// bigint. Two different organization_id values hashing to the same
	// lock key would only cost unrelated orgs a moment of unnecessary
	// serialization, never correctness — advisory lock keys are allowed
	// to collide by design.
	if _, err := r.db.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, orgKey); err != nil {
		return err
	}

	prevHash, err := r.latestHashForOrg(ctx, e.OrganizationID)
	if err != nil {
		return err
	}

	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	metadataJSON, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}

	recordHash := computeAuditRecordHash(prevHash, e, metadataJSON)

	const q = `
		INSERT INTO audit_logs (organization_id, actor_type, actor_id, action, resource_type, resource_id, result, ip_address, request_id, metadata, prev_hash, record_hash, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id`
	var id int64
	err = r.db.QueryRowContext(ctx, q,
		toNullString(e.OrganizationID), e.ActorType, toNullString(e.ActorID), e.Action,
		toNullString(e.ResourceType), toNullString(e.ResourceID), e.Result, toNullString(e.IPAddress),
		toNullString(e.RequestID), metadataJSON, sqlNullStringFromHash(prevHash), recordHash, e.OccurredAt,
	).Scan(&id)
	if err != nil {
		return translateError(err)
	}

	e.ID = strconv.FormatInt(id, 10)
	if prevHash != "" {
		e.PrevHash = &prevHash
	}
	e.RecordHash = recordHash
	return nil
}

func (r *auditLogRepository) GetByID(ctx context.Context, id string) (*entity.AuditLogEntry, error) {
	numericID, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return nil, entity.ErrNotFound
	}
	row := r.db.QueryRowContext(ctx, `SELECT `+auditLogColumns+` FROM audit_logs WHERE id = $1`, numericID)
	return scanAuditLog(row)
}

// List applies every AuditLogFilter field as a separate, independently
// optional, always-parameterized AND clause — never string concatenation
// of a value, only of $N placeholders naming a value that travels through
// database/sql's own argument binding (see placeholder's own doc
// comment). A filter field a caller doesn't set contributes no clause at
// all, rather than a clause matching "any value" some other way, so a
// query with zero filters set is simply "every event for this
// organization," not a query built by conditionally omitting WHERE 1=1
// tricks.
//
// Pagination is keyset (cursor-based), not OFFSET: f.Cursor, when set,
// decodes to the (occurred_at, id) of the last row a previous page
// returned (util.DecodeCursor — the same helper/wire-format this
// codebase already defines for this exact purpose, previously unused),
// and the next page is everything strictly after that point in the same
// ORDER BY occurred_at DESC, id DESC ordering this method has always
// used — expressed as a single row-value comparison
// "(occurred_at, id) < ($cursor_time, $cursor_id)" Postgres evaluates
// directly, not two separate inequalities a caller could get wrong by
// composing OR verses AND incorrectly. This is real cursor pagination:
// unlike an OFFSET, its cost does not grow with how deep into the result
// set a caller has paged, and a row inserted or deleted between two page
// fetches can never cause this method to skip or repeat a row the way
// OFFSET-based paging can.
//
// limit is clamped to (0, 100] the same way it always was — never treated
// as "no limit," even from a caller that forgets to set it.
func (r *auditLogRepository) List(ctx context.Context, organizationID string, f repository.AuditLogFilter) ([]*entity.AuditLogEntry, error) {
	limit := f.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	query := `SELECT ` + auditLogColumns + ` FROM audit_logs WHERE organization_id = $1`
	args := []any{organizationID}
	if f.ActorType != nil {
		args = append(args, *f.ActorType)
		query += placeholder(" AND actor_type = $", len(args))
	}
	if f.ActorID != nil {
		args = append(args, *f.ActorID)
		query += placeholder(" AND actor_id = $", len(args))
	}
	if f.Action != nil {
		args = append(args, *f.Action)
		query += placeholder(" AND action = $", len(args))
	}
	if f.ResourceType != nil {
		args = append(args, *f.ResourceType)
		query += placeholder(" AND resource_type = $", len(args))
	}
	if f.ResourceID != nil {
		args = append(args, *f.ResourceID)
		query += placeholder(" AND resource_id = $", len(args))
	}
	if f.Result != nil {
		args = append(args, *f.Result)
		query += placeholder(" AND result = $", len(args))
	}
	if f.RequestID != nil {
		args = append(args, *f.RequestID)
		query += placeholder(" AND request_id = $", len(args))
	}
	if f.OccurredAfter != nil {
		args = append(args, f.OccurredAfter.UTC())
		query += placeholder(" AND occurred_at >= $", len(args))
	}
	if f.OccurredBefore != nil {
		args = append(args, f.OccurredBefore.UTC())
		query += placeholder(" AND occurred_at < $", len(args))
	}
	if f.Cursor != nil && *f.Cursor != "" {
		cursorTime, cursorID, err := util.DecodeCursor(*f.Cursor)
		if err != nil {
			return nil, err
		}
		args = append(args, cursorTime)
		timeArgPos := len(args)
		args = append(args, cursorID)
		idArgPos := len(args)
		query += " AND (occurred_at, id) < (" + placeholder("$", timeArgPos) + ", " + placeholder("$", idArgPos) + ")"
	}
	args = append(args, limit)
	query += " ORDER BY occurred_at DESC, id DESC" + placeholder(" LIMIT $", len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*entity.AuditLogEntry
	for rows.Next() {
		e, err := scanAuditLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r *auditLogRepository) LatestHash(ctx context.Context, organizationID string) (string, error) {
	return r.latestHashForOrg(ctx, &organizationID)
}

// latestHashForOrg is Append's own lookup (org may legitimately be nil, for
// a system-level event) and LatestHash's shared implementation (org is
// always non-nil there, per that method's public signature).
func (r *auditLogRepository) latestHashForOrg(ctx context.Context, organizationID *string) (string, error) {
	var query string
	var args []any
	if organizationID == nil {
		query = `SELECT record_hash FROM audit_logs WHERE organization_id IS NULL ORDER BY id DESC LIMIT 1`
	} else {
		query = `SELECT record_hash FROM audit_logs WHERE organization_id = $1 ORDER BY id DESC LIMIT 1`
		args = []any{*organizationID}
	}
	var hash string
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return hash, err
}

const auditLogColumns = `id, organization_id, actor_type, actor_id, action, resource_type,
	resource_id, result, ip_address, request_id, metadata, prev_hash, record_hash, occurred_at`

func scanAuditLog(row interface{ Scan(dest ...any) error }) (*entity.AuditLogEntry, error) {
	var e entity.AuditLogEntry
	var id int64
	var orgID, actorID, resourceType, resourceID, ipAddress, requestID, prevHash sql.NullString
	var metadataJSON []byte
	err := row.Scan(&id, &orgID, &e.ActorType, &actorID, &e.Action, &resourceType,
		&resourceID, &e.Result, &ipAddress, &requestID, &metadataJSON, &prevHash, &e.RecordHash, &e.OccurredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, entity.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e.ID = strconv.FormatInt(id, 10)
	e.OrganizationID = nullString(orgID)
	e.ActorID = nullString(actorID)
	e.ResourceType = nullString(resourceType)
	e.ResourceID = nullString(resourceID)
	e.IPAddress = nullString(ipAddress)
	e.RequestID = nullString(requestID)
	e.PrevHash = nullString(prevHash)
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &e.Metadata); err != nil {
			return nil, err
		}
	}
	return &e, nil
}

// computeAuditRecordHash binds prevHash to every field that describes the
// event. Field values are separated by \x00 (a byte no field here can
// legitimately contain after JSON-encoding metadata) so that, e.g.,
// action="a"+resourceType="bc" can never hash identically to
// action="ab"+resourceType="c" — the concatenation is unambiguous.
func computeAuditRecordHash(prevHash string, e *entity.AuditLogEntry, metadataJSON []byte) string {
	h := sha256.New()
	writeField := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	writeField(prevHash)
	writeField(string(e.ActorType))
	if e.ActorID != nil {
		writeField(*e.ActorID)
	} else {
		writeField("")
	}
	writeField(e.Action)
	if e.ResourceType != nil {
		writeField(*e.ResourceType)
	} else {
		writeField("")
	}
	if e.ResourceID != nil {
		writeField(*e.ResourceID)
	} else {
		writeField("")
	}
	writeField(string(e.Result))
	if e.IPAddress != nil {
		writeField(*e.IPAddress)
	} else {
		writeField("")
	}
	writeField(string(metadataJSON))
	writeField(e.OccurredAt.UTC().Format(time.RFC3339Nano))
	return hex.EncodeToString(h.Sum(nil))
}

func sqlNullStringFromHash(hash string) sql.NullString {
	if hash == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: hash, Valid: true}
}
