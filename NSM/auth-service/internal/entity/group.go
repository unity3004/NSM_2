package entity

import "time"

// Group is a collection of users (team, department). ParentGroupID
// self-references Group.ID to support a hierarchy ("Platform Team" under
// "Engineering"); nil means top-level.
type Group struct {
	ID             string
	OrganizationID string
	ParentGroupID  *string
	Name           string
	Description    *string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// GroupMember is a user's membership in a group (group_members).
type GroupMember struct {
	GroupID string
	UserID  string
	AddedBy *string
	AddedAt time.Time
}

// GroupRole is a role granted to every member of a group (group_roles) —
// the "inherited via group" path to a role, as opposed to UserRole's direct
// grant. A user's effective roles are the union of both.
type GroupRole struct {
	GroupID    string
	RoleID     string
	AssignedBy *string
	AssignedAt time.Time
}
