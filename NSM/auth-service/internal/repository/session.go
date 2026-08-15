package repository

import (
	"context"
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// SessionRepository persists entity.Session.
type SessionRepository interface {
	Create(ctx context.Context, s *entity.Session) error
	GetByID(ctx context.Context, id string) (*entity.Session, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*entity.Session, error)
	ListActiveByUser(ctx context.Context, userID string) ([]*entity.Session, error)
	Touch(ctx context.Context, id string, lastActiveAt time.Time) error
	Revoke(ctx context.Context, id string, reason entity.RevocationReason) error
	RevokeAllForUser(ctx context.Context, userID string, reason entity.RevocationReason) error
}

// RefreshTokenRepository persists entity.RefreshToken and implements the
// rotation-with-reuse-detection primitive: RevokeFamily is what runs when
// AlreadyRotated is true on a presented token.
type RefreshTokenRepository interface {
	Create(ctx context.Context, t *entity.RefreshToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error)
	// Rotate atomically marks `current` revoked-with-replacement and inserts
	// `next` in one transaction — see postgres.refreshTokenRepository.Rotate.
	Rotate(ctx context.Context, current *entity.RefreshToken, next *entity.RefreshToken) error
	RevokeFamily(ctx context.Context, familyID string, reason entity.RevocationReason) error
}
