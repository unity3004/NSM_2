package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
)

// RBACService is the first real authorization enforcement point in this
// codebase — see internal/repository/rbac.go's own doc comment for how it
// was, until this sprint, schema and interfaces with no service or
// Postgres implementation behind them.
//
// Every check is a real-time database query (RBACRepository.UserHasPermission),
// never a cached or JWT-embedded decision — util.Claims does carry a
// Permissions field, populated at token-issuance time, but nothing here
// reads it. A revoked role must take effect on the very next request, not
// after the caller's access token happens to expire or refresh; the cost
// is one extra query per authorization check, which this codebase's own
// "backend remains authoritative" precedent (the frontend's real-time
// refresh-on-401 design, this same sprint's platform-status check) already
// treats as the correct trade to make.
type RBACService struct {
	rbac repository.RBACRepository
}

func NewRBACService(rbac repository.RBACRepository) *RBACService {
	return &RBACService{rbac: rbac}
}

// HasPermission reports whether userID currently holds permission
// ("resource:action", e.g. "users:create") via any non-expired direct
// role grant. Malformed input (missing the ':' separator) is a
// programming error in the caller — every call site in this codebase
// passes a compile-time string constant — reported as an error rather
// than silently denied or allowed, so it fails loudly in development
// instead of masquerading as "this user lacks permission" in production.
func (s *RBACService) HasPermission(ctx context.Context, userID, permission string) (bool, error) {
	resource, action, ok := strings.Cut(permission, ":")
	if !ok {
		return false, fmt.Errorf("service: malformed permission string %q (want \"resource:action\")", permission)
	}
	return s.rbac.UserHasPermission(ctx, userID, resource, action)
}

// EffectivePermissions returns every permission userID currently holds —
// backs the user detail page's "permissions derived from roles" display.
func (s *RBACService) EffectivePermissions(ctx context.Context, userID string) ([]*entity.Permission, error) {
	return s.rbac.UserPermissions(ctx, userID)
}

// HasServiceAccountPermission is HasPermission's machine-identity mirror
// (Sprint 5 Task 1) — every caller that needs to authorize a request
// branches between this and HasPermission based on
// util.Claims.IsServiceAccount(), never guesses from the ID's shape alone
// (a service account ID and a user ID are both opaque UUIDs — nothing
// about the string itself says which table it belongs to).
func (s *RBACService) HasServiceAccountPermission(ctx context.Context, serviceAccountID, permission string) (bool, error) {
	resource, action, ok := strings.Cut(permission, ":")
	if !ok {
		return false, fmt.Errorf("service: malformed permission string %q (want \"resource:action\")", permission)
	}
	return s.rbac.ServiceAccountHasPermission(ctx, serviceAccountID, resource, action)
}

// ServiceAccountEffectivePermissions is EffectivePermissions' machine-identity
// mirror — backs the service account detail page's own permissions display.
func (s *RBACService) ServiceAccountEffectivePermissions(ctx context.Context, serviceAccountID string) ([]*entity.Permission, error) {
	return s.rbac.ServiceAccountPermissions(ctx, serviceAccountID)
}
