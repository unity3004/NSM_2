//go:build integration

package integration

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/database"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/util"
)

// appendAuditEntry writes e via a real transaction, the same way every
// production caller does (see postgres.NewAuditLogRepository's own doc
// comment on why Append's advisory lock only does its job inside a
// transaction) — never against a bare *sql.DB directly.
func appendAuditEntry(t *testing.T, db *sql.DB, e *entity.AuditLogEntry) {
	t.Helper()
	err := database.WithTx(context.Background(), db, func(tx *sql.Tx) error {
		return postgres.NewAuditLogRepository(tx).Append(context.Background(), e)
	})
	if err != nil {
		t.Fatalf("Append(%q): %v", e.Action, err)
	}
}

func auditReadRepo(db *sql.DB) repository.AuditLogRepository {
	return postgres.NewAuditLogRepository(db)
}

// 1. request_id round-trips and is queryable — the objective's own
// request-correlation requirement, against the real column/index this
// task's migration 000029 added.
func TestAuditRepository_RequestID_PersistsAndFilters(t *testing.T) {
	db := connectForRegisterTest(t)
	reqID := "req-it-" + t.Name()
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID),
		ActorType:      entity.AuditActorUser,
		Action:         "secret.read",
		Result:         entity.AuditResultSuccess,
		RequestID:      strPtrForTest(reqID),
	})
	// A second, unrelated entry with a different request ID must never
	// show up in a request_id-filtered query.
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID),
		ActorType:      entity.AuditActorUser,
		Action:         "secret.read",
		Result:         entity.AuditResultSuccess,
		RequestID:      strPtrForTest("req-it-unrelated-" + t.Name()),
	})

	got, err := auditReadRepo(db).List(context.Background(), secretTestOrgID, repository.AuditLogFilter{RequestID: &reqID, Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List(request_id=%q) returned %d rows, want 1", reqID, len(got))
	}
	if got[0].RequestID == nil || *got[0].RequestID != reqID {
		t.Errorf("RequestID = %v, want %q", got[0].RequestID, reqID)
	}
}

// 2. Action (event type) filter — previously impossible to filter by at all.
func TestAuditRepository_List_FiltersByAction(t *testing.T) {
	db := connectForRegisterTest(t)
	marker := "it-action-" + t.Name()
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "secret.deleted", ResourceType: strPtrForTest(marker), Result: entity.AuditResultSuccess,
	})
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "secret.read", ResourceType: strPtrForTest(marker), Result: entity.AuditResultSuccess,
	})

	action := "secret.deleted"
	resourceType := marker
	got, err := auditReadRepo(db).List(context.Background(), secretTestOrgID,
		repository.AuditLogFilter{Action: &action, ResourceType: &resourceType, Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 1 || got[0].Action != "secret.deleted" {
		t.Fatalf("List(action=secret.deleted) = %+v, want exactly one secret.deleted row", got)
	}
}

// TestAuditRepository_CountByResult_ReflectsFullFilteredSetAgainstRealDB is
// the Audit Explorer summary cards' own real-Postgres proof: the grouped
// COUNT query filters by the same ResourceType marker every other test in
// this file uses for isolation, and must total every matching row
// regardless of Limit — a real GROUP BY against the real audit_logs
// table, not the in-memory fake's own reimplementation of the same logic
// (see mocks.FakeAuditLogRepository.CountByResult).
func TestAuditRepository_CountByResult_ReflectsFullFilteredSetAgainstRealDB(t *testing.T) {
	db := connectForRegisterTest(t)
	marker := "it-countbyresult-" + t.Name()
	for range 3 {
		appendAuditEntry(t, db, &entity.AuditLogEntry{
			OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
			Action: "secret.read", ResourceType: strPtrForTest(marker), Result: entity.AuditResultSuccess,
		})
	}
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "user.login", ResourceType: strPtrForTest(marker), Result: entity.AuditResultFailure,
	})
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "authorization.denied", ResourceType: strPtrForTest(marker), Result: entity.AuditResultDenied,
	})

	resourceType := marker
	counts, err := auditReadRepo(db).CountByResult(context.Background(), secretTestOrgID,
		repository.AuditLogFilter{ResourceType: &resourceType, Limit: 1})
	if err != nil {
		t.Fatalf("CountByResult() error = %v", err)
	}
	if counts[entity.AuditResultSuccess] != 3 {
		t.Errorf("counts[success] = %d, want 3 (Limit must not shrink a count)", counts[entity.AuditResultSuccess])
	}
	if counts[entity.AuditResultFailure] != 1 {
		t.Errorf("counts[failure] = %d, want 1", counts[entity.AuditResultFailure])
	}
	if counts[entity.AuditResultDenied] != 1 {
		t.Errorf("counts[denied] = %d, want 1", counts[entity.AuditResultDenied])
	}
}

// 3. Time-range filtering — OccurredAfter/OccurredBefore were previously
// accepted by the filter struct but silently ignored by the SQL; this
// proves they now actually bound the query.
func TestAuditRepository_List_FiltersByTimeRange(t *testing.T) {
	db := connectForRegisterTest(t)
	marker := "it-timerange-" + t.Name()
	now := time.Now().UTC()

	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "secret.read", ResourceType: strPtrForTest(marker), Result: entity.AuditResultSuccess,
		OccurredAt: now.Add(-2 * time.Hour),
	})
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "secret.read", ResourceType: strPtrForTest(marker), Result: entity.AuditResultSuccess,
		OccurredAt: now,
	})

	after := now.Add(-1 * time.Hour)
	resourceType := marker
	got, err := auditReadRepo(db).List(context.Background(), secretTestOrgID,
		repository.AuditLogFilter{ResourceType: &resourceType, OccurredAfter: &after, Limit: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("List(occurred_after=%s) returned %d rows, want exactly the one row after the cutoff", after, len(got))
	}
	if got[0].OccurredAt.Before(after) {
		t.Errorf("returned row OccurredAt = %s, which is before the occurred_after cutoff %s", got[0].OccurredAt, after)
	}
}

// 4. Real cursor pagination against real Postgres — the (occurred_at, id)
// row-value keyset comparison, not the fake's simplified ID-lookup
// substitute (see FakeAuditLogRepository.List's own doc comment on that
// difference).
func TestAuditRepository_List_CursorPagination(t *testing.T) {
	db := connectForRegisterTest(t)
	marker := "it-cursor-" + t.Name()
	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		appendAuditEntry(t, db, &entity.AuditLogEntry{
			OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
			Action: "secret.read", ResourceType: strPtrForTest(marker), Result: entity.AuditResultSuccess,
			OccurredAt: base.Add(time.Duration(i) * time.Second),
		})
	}

	resourceType := marker
	repo := auditReadRepo(db)
	seen := map[string]bool{}
	var cursor *string
	pages := 0
	for {
		pages++
		if pages > 10 {
			t.Fatal("pagination did not terminate within 10 pages — likely an infinite loop or a broken cursor")
		}
		filter := repository.AuditLogFilter{ResourceType: &resourceType, Limit: 2, Cursor: cursor}
		page, err := repo.List(context.Background(), secretTestOrgID, filter)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Errorf("entry %s appeared on more than one page", e.ID)
			}
			seen[e.ID] = true
		}
		last := page[len(page)-1]
		c := util.EncodeCursor(last.OccurredAt, last.ID)
		cursor = &c
		if len(page) < 2 {
			break
		}
	}
	if len(seen) != 5 {
		t.Errorf("saw %d distinct entries across all pages, want 5", len(seen))
	}
}

// 5. Central redaction is applied at Append — a metadata key that looks
// sensitive by name never reaches the stored row, regardless of which
// caller constructed it.
func TestAuditRepository_Append_RedactsSensitiveMetadata(t *testing.T) {
	db := connectForRegisterTest(t)
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "secret.created", Result: entity.AuditResultSuccess,
		Metadata: map[string]any{"path": "prod/db", "password": "should-never-be-stored"},
	})

	var metadataJSON string
	err := db.QueryRow(`SELECT metadata::text FROM audit_logs WHERE action = 'secret.created' AND organization_id = $1 ORDER BY id DESC LIMIT 1`, secretTestOrgID).Scan(&metadataJSON)
	if err != nil {
		t.Fatalf("query stored metadata: %v", err)
	}
	if !strings.Contains(metadataJSON, "REDACTED") {
		t.Errorf("stored metadata = %s, want the password key redacted", metadataJSON)
	}
	if strings.Contains(metadataJSON, "should-never-be-stored") {
		t.Errorf("stored metadata = %s, contains the raw password value — redaction did not apply", metadataJSON)
	}
}

// 6/7. Immutability: the database itself rejects UPDATE and DELETE on
// audit_logs, regardless of which role or code path attempts it — see
// migrations/000029's own doc comment on why this is enforced as a
// trigger, not only "the application's Go code has no Update/Delete
// method."
func TestAuditRepository_ImmutabilityTrigger_RejectsUpdate(t *testing.T) {
	db := connectForRegisterTest(t)
	var id int64
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "secret.read", Result: entity.AuditResultSuccess,
	})
	if err := db.QueryRow(`SELECT id FROM audit_logs WHERE organization_id = $1 ORDER BY id DESC LIMIT 1`, secretTestOrgID).Scan(&id); err != nil {
		t.Fatalf("look up inserted row id: %v", err)
	}

	_, err := db.Exec(`UPDATE audit_logs SET action = 'tampered' WHERE id = $1`, id)
	if err == nil {
		t.Fatal("UPDATE audit_logs succeeded — immutability trigger did not fire")
	}
}

func TestAuditRepository_ImmutabilityTrigger_RejectsDelete(t *testing.T) {
	db := connectForRegisterTest(t)
	var id int64
	appendAuditEntry(t, db, &entity.AuditLogEntry{
		OrganizationID: strPtrForTest(secretTestOrgID), ActorType: entity.AuditActorUser,
		Action: "secret.read", Result: entity.AuditResultSuccess,
	})
	if err := db.QueryRow(`SELECT id FROM audit_logs WHERE organization_id = $1 ORDER BY id DESC LIMIT 1`, secretTestOrgID).Scan(&id); err != nil {
		t.Fatalf("look up inserted row id: %v", err)
	}

	_, err := db.Exec(`DELETE FROM audit_logs WHERE id = $1`, id)
	if err == nil {
		t.Fatal("DELETE FROM audit_logs succeeded — immutability trigger did not fire")
	}

	// The row must still be exactly there, unaffected by the rejected attempt.
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM audit_logs WHERE id = $1`, id).Scan(&count); err != nil {
		t.Fatalf("count after rejected delete: %v", err)
	}
	if count != 1 {
		t.Errorf("row count after rejected DELETE = %d, want 1 (row must be untouched)", count)
	}
}

// 8. Hash chain still holds with the new column present — a regression
// guard that adding request_id didn't silently break Append's existing
// tamper-evidence mechanism.
func TestAuditRepository_HashChain_StillLinksSequentialEntries(t *testing.T) {
	db := connectForRegisterTest(t)
	orgID := secretTestOrgID
	repo := postgres.NewAuditLogRepository(db)

	before, err := repo.LatestHash(context.Background(), orgID)
	if err != nil {
		t.Fatalf("LatestHash() before: %v", err)
	}

	first := &entity.AuditLogEntry{OrganizationID: &orgID, ActorType: entity.AuditActorUser, Action: "secret.read", Result: entity.AuditResultSuccess}
	appendAuditEntry(t, db, first)
	if before != "" && (first.PrevHash == nil || *first.PrevHash != before) {
		t.Errorf("first.PrevHash = %v, want %q (the chain's tail before this Append)", first.PrevHash, before)
	}

	second := &entity.AuditLogEntry{OrganizationID: &orgID, ActorType: entity.AuditActorUser, Action: "secret.read", Result: entity.AuditResultSuccess}
	appendAuditEntry(t, db, second)
	if second.PrevHash == nil || *second.PrevHash != first.RecordHash {
		t.Errorf("second.PrevHash = %v, want %q (first.RecordHash)", second.PrevHash, first.RecordHash)
	}
}
