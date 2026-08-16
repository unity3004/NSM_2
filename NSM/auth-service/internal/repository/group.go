package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// GroupRepository persists entity.Group, its membership, and the roles it
// confers on members.
type GroupRepository interface {
	Create(ctx context.Context, g *entity.Group) error
	GetByID(ctx context.Context, id string) (*entity.Group, error)
	List(ctx context.Context, organizationID string, parentGroupID *string, cursor *string, limit int) ([]*entity.Group, error)
	Update(ctx context.Context, g *entity.Group) error
	Delete(ctx context.Context, id string) error

	AddMember(ctx context.Context, m *entity.GroupMember) error
	RemoveMember(ctx context.Context, groupID, userID string) error
	ListMembers(ctx context.Context, groupID string, cursor *string, limit int) ([]*entity.GroupMember, error)

	GrantRole(ctx context.Context, gr *entity.GroupRole) error
	RevokeRole(ctx context.Context, groupID, roleID string) error
	ListRoles(ctx context.Context, groupID string) ([]*entity.GroupRole, error)

	// ListGroupIDsForUser powers effective-permission resolution: the
	// service layer unions UserRepository.ListRoles with GroupRole grants
	// for every group ID this returns.
	ListGroupIDsForUser(ctx context.Context, userID string) ([]string, error)
}
