package entity

import "time"

// ServiceAccountStatus mirrors the service_account_status Postgres enum.
type ServiceAccountStatus string

const (
	ServiceAccountStatusActive   ServiceAccountStatus = "active"
	ServiceAccountStatusDisabled ServiceAccountStatus = "disabled"
)

// ServiceAccount is a machine/workload principal — the non-human counterpart
// to User. It is a distinct type rather than a "User with a flag" because it
// has no password, no MFA, and no session in the human sense; modeling it
// separately keeps those columns from being nullable-for-half-the-table on
// User.
type ServiceAccount struct {
	ID                  string
	OrganizationID      string
	Name                string
	Description         *string
	Status              ServiceAccountStatus
	CreatedBy           *string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	// LastAuthenticatedAt is nil until the first successful machine
	// authentication (ServiceAccountService.Authenticate) and updated on
	// every one thereafter — never touched by admin operations (create,
	// role grants, credential issuance) that don't themselves constitute
	// the service account actually authenticating.
	LastAuthenticatedAt *time.Time
}

// ServiceAccountRole is a role grant to a service account (service_account_roles).
type ServiceAccountRole struct {
	ServiceAccountID string
	RoleID           string
	AssignedBy       *string
	AssignedAt       time.Time
}
