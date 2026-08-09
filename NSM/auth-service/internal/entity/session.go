package entity

import "time"

// RevocationReason mirrors the token_revocation_reason Postgres enum.
type RevocationReason string

const (
	RevocationLogout        RevocationReason = "logout"
	RevocationRotation      RevocationReason = "rotation"
	RevocationReuseDetected RevocationReason = "reuse_detected"
	RevocationAdminRevoked  RevocationReason = "admin_revoked"
	RevocationExpired       RevocationReason = "expired"
	RevocationPasswordReset RevocationReason = "password_reset"
	RevocationBreakglass    RevocationReason = "breakglass"
)

// Session is one authenticated human login (web/CLI). Only a hash of the
// bearer/session token is ever stored — see util.HashToken.
type Session struct {
	ID                string
	UserID            string
	SessionTokenHash  string
	IPAddress         *string
	UserAgent         *string
	DeviceFingerprint *string
	CreatedAt         time.Time
	LastActiveAt      time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	RevokedReason     *RevocationReason
}

func (s *Session) IsActive(now time.Time) bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(now)
}

// RefreshToken belongs to the Session that minted it. FamilyID groups every
// token descended from one original login; ParentTokenID / ReplacedByTokenID
// form the rotation chain. Presenting a token whose ReplacedByTokenID is
// already set is the signature of token theft — see
// service.AuthService.RefreshToken, which revokes the whole FamilyID when
// that happens.
type RefreshToken struct {
	ID                string
	SessionID         string
	UserID            string
	TokenHash         string
	FamilyID          string
	ParentTokenID     *string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	RevokedReason     *RevocationReason
	ReplacedByTokenID *string
}

func (t *RefreshToken) IsExpired(now time.Time) bool {
	return t.ExpiresAt.Before(now)
}

// AlreadyRotated reports whether this token has already been exchanged once
// — the reuse-detection signal.
func (t *RefreshToken) AlreadyRotated() bool {
	return t.ReplacedByTokenID != nil
}
