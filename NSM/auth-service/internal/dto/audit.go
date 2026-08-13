package dto

import (
	"time"

	"github.com/acme/auth-service/internal/entity"
)

// AuditLogResponse matches components.schemas.AuditLogEntry. PrevHash and
// RecordHash are exposed deliberately — an auditor or an automated integrity
// job needs them to independently verify the tamper-evident chain; hiding
// the mechanism would defeat the point of publishing it. Metadata already
// passed through entity.SanitizeAuditMetadata before it was ever
// persisted (postgres.auditLogRepository.Append) — this response
// serializes exactly what's stored, never a second, independent
// filtering pass that could disagree with what the write path enforced.
type AuditLogResponse struct {
	ID             string         `json:"id"`
	OrganizationID *string        `json:"organization_id,omitempty"`
	ActorType      string         `json:"actor_type"`
	ActorID        *string        `json:"actor_id,omitempty"`
	Action         string         `json:"action"`
	ResourceType   *string        `json:"resource_type,omitempty"`
	ResourceID     *string        `json:"resource_id,omitempty"`
	Result         string         `json:"result"`
	IPAddress      *string        `json:"ip_address,omitempty"`
	RequestID      *string        `json:"request_id,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
	PrevHash       *string        `json:"prev_hash,omitempty"`
	RecordHash     string         `json:"record_hash"`
	OccurredAt     time.Time      `json:"occurred_at"`
}

func AuditLogResponseFromEntity(e *entity.AuditLogEntry) AuditLogResponse {
	return AuditLogResponse{
		ID:             e.ID,
		OrganizationID: e.OrganizationID,
		ActorType:      string(e.ActorType),
		ActorID:        e.ActorID,
		Action:         e.Action,
		ResourceType:   e.ResourceType,
		ResourceID:     e.ResourceID,
		Result:         string(e.Result),
		IPAddress:      e.IPAddress,
		RequestID:      e.RequestID,
		Metadata:       e.Metadata,
		PrevHash:       e.PrevHash,
		RecordHash:     e.RecordHash,
		OccurredAt:     e.OccurredAt,
	}
}

// LoginHistoryResponse matches components.schemas.LoginHistoryEntry.
type LoginHistoryResponse struct {
	ID                  string    `json:"id"`
	OrganizationID      *string   `json:"organization_id,omitempty"`
	UserID              *string   `json:"user_id,omitempty"`
	AttemptedIdentifier *string   `json:"attempted_identifier,omitempty"`
	Status              string    `json:"status"`
	AuthMethod          string    `json:"auth_method"`
	IPAddress           *string   `json:"ip_address,omitempty"`
	SessionID           *string   `json:"session_id,omitempty"`
	OccurredAt          time.Time `json:"occurred_at"`
}

// AuditLogQuery matches the query parameters on GET /v1/audit-logs —
// every filter repository.AuditLogFilter supports, at the HTTP boundary.
// Every field is a plain string/time on the wire; translating "success"/
// "failure"/"denied" into entity.AuditResult (and similarly for
// ActorType) happens once, in auditHandler.list, so a malformed enum
// value is reported as a 422 with a field name before it ever reaches
// the service or repository layer.
type AuditLogQuery struct {
	ActorType      *string
	ActorID        *string
	Action         *string
	ResourceType   *string
	ResourceID     *string
	Result         *string
	RequestID      *string
	OccurredAfter  *time.Time
	OccurredBefore *time.Time
	Limit          int
	Cursor         *string
}

// maxAuditQuerySpan bounds how wide an explicit occurred_after/
// occurred_before window may be (Sprint 4 Task 4's own "time-range
// limits where appropriate" requirement) — defense-in-depth alongside
// the Limit bound below and the rate limiter guarding this route
// (categoryAuditRead, router.go): pagination already caps how many rows
// any single request can return regardless of how wide a time range is
// given, so this exists purely to reject a query shaped like "give me
// every event since the epoch," which is never a legitimate
// investigative query and is cheap to reject outright before it reaches
// the database at all.
const maxAuditQuerySpan = 366 * 24 * time.Hour

func (q AuditLogQuery) Validate() error {
	var errs ValidationErrors
	if q.OccurredAfter != nil && q.OccurredBefore != nil {
		if q.OccurredAfter.After(*q.OccurredBefore) {
			errs.Add("occurred_after", "must not be after occurred_before")
		} else if q.OccurredBefore.Sub(*q.OccurredAfter) > maxAuditQuerySpan {
			errs.Add("occurred_after", "the range between occurred_after and occurred_before must not exceed 366 days")
		}
	}
	if q.Limit < 1 || q.Limit > 100 {
		errs.Add("limit", "must be between 1 and 100")
	}
	if q.ActorType != nil {
		switch *q.ActorType {
		case "user", "service_account", "api_key", "system":
		default:
			errs.Add("actor_type", `must be one of "user", "service_account", "api_key", "system"`)
		}
	}
	if q.Result != nil {
		switch *q.Result {
		case "success", "failure", "denied":
		default:
			errs.Add("result", `must be one of "success", "failure", "denied"`)
		}
	}
	return errs.Err()
}
