package repository

import (
	"context"

	"github.com/acme/auth-service/internal/entity"
)

// OrganizationRepository persists entity.Organization. There is no Delete —
// see the API design note on hard-delete: an organization is suspended or
// soft-deleted (a status flip), never removed, because users.organization_id
// is ON DELETE RESTRICT by design.
type OrganizationRepository interface {
	Create(ctx context.Context, o *entity.Organization) error
	GetByID(ctx context.Context, id string) (*entity.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*entity.Organization, error)
	Update(ctx context.Context, o *entity.Organization) error
}
