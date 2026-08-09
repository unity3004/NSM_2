package entity

import "time"

// LoginStatus mirrors the login_status Postgres enum.
type LoginStatus string

const (
	LoginSuccess                LoginStatus = "success"
	LoginFailureBadPassword     LoginStatus = "failure_bad_password"
	LoginFailureMFA             LoginStatus = "failure_mfa"
	LoginFailureLocked          LoginStatus = "failure_locked"
	LoginFailureDisabled        LoginStatus = "failure_disabled"
	LoginFailureUnknownIdentity LoginStatus = "failure_unknown_identity"
	LoginFailureOther           LoginStatus = "failure_other"
)

// AuthMethod mirrors the auth_method Postgres enum.
type AuthMethod string

const (
	AuthMethodPassword            AuthMethod = "password"
	AuthMethodSSOOIDC             AuthMethod = "sso_oidc"
	AuthMethodSSOSAML             AuthMethod = "sso_saml"
	AuthMethodAPIKey              AuthMethod = "api_key"
	AuthMethodServiceAccountToken AuthMethod = "service_account_token"
	AuthMethodWebAuthn            AuthMethod = "webauthn"
)

// LoginHistoryEntry is an append-only record of one authentication attempt,
// success or failure. UserID is nil when the attempt targeted an unknown
// identity — AttemptedIdentifier preserves what was typed so brute-force /
// enumeration detection still has something to key on.
type LoginHistoryEntry struct {
	ID                  string
	OrganizationID      *string
	UserID              *string
	AttemptedIdentifier *string
	Status              LoginStatus
	AuthMethod          AuthMethod
	IPAddress           *string
	UserAgent           *string
	SessionID           *string
	OccurredAt          time.Time
}

// AuditActorType mirrors the audit_actor_type Postgres enum.
type AuditActorType string

const (
	AuditActorUser           AuditActorType = "user"
	AuditActorServiceAccount AuditActorType = "service_account"
	AuditActorAPIKey         AuditActorType = "api_key"
	AuditActorSystem         AuditActorType = "system"
)

// AuditResult mirrors the audit_result Postgres enum.
type AuditResult string

const (
	AuditResultSuccess AuditResult = "success"
	AuditResultFailure AuditResult = "failure"
	AuditResultDenied  AuditResult = "denied"
)

// AuditLogEntry is an immutable, tamper-evident record of one
// security-relevant action. ActorID is deliberately polymorphic (resolved
// against User/ServiceAccount/APIKey by ActorType) rather than a foreign
// key — see auth-service-database-schema.md §"audit_logs". PrevHash /
// RecordHash form the hash chain that makes the log independently
// verifiable; Metadata never contains secret values.
type AuditLogEntry struct {
	ID             string
	OrganizationID *string
	ActorType      AuditActorType
	ActorID        *string
	Action         string
	ResourceType   *string
	ResourceID     *string
	Result         AuditResult
	IPAddress      *string
	Metadata       map[string]any
	PrevHash       *string
	RecordHash     string
	OccurredAt     time.Time
}
