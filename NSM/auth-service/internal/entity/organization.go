package entity

import "time"

// OrgStatus mirrors the org_status Postgres enum in auth_service_schema.sql.
type OrgStatus string

const (
	OrgStatusActive    OrgStatus = "active"
	OrgStatusSuspended OrgStatus = "suspended"
	OrgStatusDeleted   OrgStatus = "deleted"
)

// Organization is the tenant boundary. Every other principal, role, and
// group in the system is scoped to exactly one Organization (system-wide
// roles excepted — see Role.OrganizationID).
type Organization struct {
	ID        string
	Name      string
	Slug      string
	Status    OrgStatus
	CreatedAt time.Time
	UpdatedAt time.Time
}
