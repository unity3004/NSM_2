package dto

import "time"

// AuditLogResponse matches components.schemas.AuditLogEntry. PrevHash and
// RecordHash are exposed deliberately — an auditor or an automated integrity
// job needs them to independently verify the tamper-evident chain; hiding
// the mechanism would defeat the point of publishing it.
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
	Metadata       map[string]any `json:"metadata,omitempty"`
	PrevHash       *string        `json:"prev_hash,omitempty"`
	RecordHash     string         `json:"record_hash"`
	OccurredAt     time.Time      `json:"occurred_at"`
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

// AuditLogQuery matches the query parameters on GET /audit-logs.
type AuditLogQuery struct {
	ActorType      *string
	ActorID        *string
	ResourceType   *string
	ResourceID     *string
	Result         *string
	OccurredAfter  *time.Time
	OccurredBefore *time.Time
	Limit          int
	Cursor         *string
}

func (q AuditLogQuery) Validate() error {
	var errs ValidationErrors
	if q.OccurredAfter != nil && q.OccurredBefore != nil && q.OccurredAfter.After(*q.OccurredBefore) {
		errs.Add("occurred_after", "must not be after occurred_before")
	}
	if q.Limit < 1 || q.Limit > 100 {
		errs.Add("limit", "must be between 1 and 100")
	}
	return errs.Err()
}
