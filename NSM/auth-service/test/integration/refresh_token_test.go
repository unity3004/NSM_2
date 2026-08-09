//go:build integration

package integration

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository/postgres"
	"github.com/acme/auth-service/internal/util"
)

const refreshTestOrgID = "00000000-0000-4000-8000-000000000001"

// seedUserSessionAndRefreshToken creates the full chain of real rows a
// refresh token's foreign keys require (users -> sessions ->
// refresh_tokens) and returns the current token entity plus its raw
// (pre-hash) value.
func seedUserSessionAndRefreshToken(t *testing.T, db *sql.DB) (*entity.RefreshToken, string) {
	t.Helper()
	ctx := context.Background()
	users := postgres.NewUserRepository(db)
	sessions := postgres.NewSessionRepository(db)
	refreshTokens := postgres.NewRefreshTokenRepository(db)

	email := "refresh-it-" + t.Name() + "@example.com"
	user := &entity.User{OrganizationID: refreshTestOrgID, Email: email, Status: entity.UserStatusActive}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	sessionRaw, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	session := &entity.Session{
		UserID:           user.ID,
		SessionTokenHash: util.HashToken(sessionRaw),
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	if err := sessions.Create(ctx, session); err != nil {
		t.Fatalf("create session: %v", err)
	}

	raw, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	rt := &entity.RefreshToken{
		SessionID: session.ID,
		UserID:    user.ID,
		TokenHash: util.HashToken(raw),
		FamilyID:  util.NewUUID(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := refreshTokens.Create(ctx, rt); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	return rt, raw
}

// TestRefreshTokenRepository_ConcurrentRotateOnlyOneWins is the real-database
// half of requirements #14/#15/#17:
// internal/service/refresh_token_service_test.go's
// TestRefreshTokenService_Refresh_ConcurrentRequestsOnlyOneSucceeds proves
// RefreshTokenService's own handling of a losing race against the fake's
// mutex-serialized Rotate; this test proves Postgres's own
// "UPDATE ... WHERE revoked_at IS NULL" row locking actually serializes
// concurrent transactions rather than letting both succeed, which a fake
// cannot prove no matter how it's written.
func TestRefreshTokenRepository_ConcurrentRotateOnlyOneWins(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	refreshTokens := postgres.NewRefreshTokenRepository(db)
	current, _ := seedUserSessionAndRefreshToken(t, db)

	const concurrency = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nextRaw, err := util.NewOpaqueToken()
			if err != nil {
				t.Errorf("NewOpaqueToken: %v", err)
				return
			}
			next := &entity.RefreshToken{
				SessionID:     current.SessionID,
				UserID:        current.UserID,
				TokenHash:     util.HashToken(nextRaw),
				FamilyID:      current.FamilyID,
				ParentTokenID: &current.ID,
				ExpiresAt:     time.Now().Add(time.Hour),
			}
			if err := refreshTokens.Rotate(ctx, current, next); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("successes = %d, want exactly 1 — Postgres row locking must serialize concurrent Rotate calls on the same token", successes)
	}
}

// TestRefreshTokenRepository_RotateRollsBackOnFailure is the real-database
// half of requirement #18: forcing the INSERT half of Rotate to fail (an
// invalid session_id, rejected by the foreign key) must leave the current
// token exactly as it was — still un-revoked — proving the two statements
// inside Rotate commit or roll back together, not independently.
func TestRefreshTokenRepository_RotateRollsBackOnFailure(t *testing.T) {
	db := connectForRegisterTest(t)
	ctx := context.Background()
	refreshTokens := postgres.NewRefreshTokenRepository(db)
	current, _ := seedUserSessionAndRefreshToken(t, db)

	badNextRaw, err := util.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken: %v", err)
	}
	next := &entity.RefreshToken{
		SessionID:     "00000000-0000-4000-8000-000000000000", // no such session: rejected by the foreign key
		UserID:        current.UserID,
		TokenHash:     util.HashToken(badNextRaw),
		FamilyID:      current.FamilyID,
		ParentTokenID: &current.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := refreshTokens.Rotate(ctx, current, next); err == nil {
		t.Fatal("Rotate() with an invalid session_id on the next token = nil error, want a foreign-key failure")
	}

	stored, err := refreshTokens.GetByTokenHash(ctx, current.TokenHash)
	if err != nil {
		t.Fatalf("GetByTokenHash() error = %v", err)
	}
	if stored.RevokedAt != nil {
		t.Error("current token was revoked despite Rotate's INSERT half failing — the transaction did not roll back")
	}
}
