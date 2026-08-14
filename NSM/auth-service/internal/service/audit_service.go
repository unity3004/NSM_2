package service

import (
	"context"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// permAuditRead is the existing "audit:read" permission (migrations
// 000022/000023) — already seeded to Security Engineer and Auditor,
// reused here rather than inventing a second permission for the same
// concept: "who may look at security evidence" is exactly what audit:read
// already means, and this service is the first thing to actually gate a
// route behind it.
const permAuditRead = "audit:read"

// AuditService is Sprint 4 Task 3's read side of the audit trail:
// authorized administrators listing and filtering audit_logs. It writes
// nothing to audit_logs on behalf of any other service — every other
// service in this codebase already appends its own events directly via
// AuditTxFunc (see e.g. SecretService.recordSecretAudit) — the one
// exception being this service's own access to the trail, which it
// records about itself (recordAuditAccess, "admin.audit.read"): viewing
// security evidence is itself a security-relevant event, per this
// sprint's own objective ("Audit viewing itself should be audited").
//
// Like SecretService and SecretPolicyService, this performs its own
// internal RBAC check rather than trusting middleware.RequirePermission
// alone — defense-in-depth for what is, by construction, the most
// sensitive read surface in this application (every other security event
// this system ever recorded, in one place).
type AuditService struct {
	repo    repository.AuditLogRepository
	rbac    *RBACService
	auditTx AuditTxFunc
}

// NewAuditService constructs an AuditService. auditTx may be nil (the
// same allowance every other AuditTxFunc dependency in this codebase
// makes) — ListAuditLogs still enforces authorization and returns
// results without it, it just doesn't get an admin.audit.read trail of
// its own.
func NewAuditService(repo repository.AuditLogRepository, rbac *RBACService, auditTx AuditTxFunc) *AuditService {
	return &AuditService{repo: repo, rbac: rbac, auditTx: auditTx}
}

// AuditLogPage is ListAuditLogs' return value — entries plus enough to
// build the next request, mirroring the dto.PageMeta shape this codebase
// already uses for every other paginated list endpoint (secrets, in
// particular) rather than inventing a second pagination envelope.
type AuditLogPage struct {
	Entries    []*entity.AuditLogEntry
	NextCursor string
	HasMore    bool
	// Counts is the Audit Explorer's own "Total / Successful / Failed /
	// Denied" summary — computed across every row the caller's filters
	// match (Cursor/Limit excluded), never just the entries on this one
	// page. A result value with a zero count is simply absent from this
	// map, never a zero-valued entry.
	Counts map[entity.AuditResult]int
}

// ListAuditLogs is the one place a caller reads audit_logs through this
// service. It always fetches one row more than requested
// (fetchFilter.Limit = requestedLimit+1): getting requestedLimit+1 rows
// back means there is a next page, and the extra row's own
// (OccurredAt, ID) becomes NextCursor (util.EncodeCursor) — the same
// row-value keyset comparison postgresAuditLogRepository.List already
// implements server-side, never an OFFSET whose cost grows with how deep
// a caller has paged. requestedLimit itself is clamped the same way the
// repository's own Limit clamp already is (<=0 or >100 -> 20) — this
// clamp exists here too so AuditLogPage's own bookkeeping (requestedLimit
// vs. len(entries)) uses the exact value that was actually applied, not
// whatever a caller passed in unclamped.
func (s *AuditService) ListAuditLogs(ctx context.Context, actorUserID, organizationID string, filter repository.AuditLogFilter, ipAddress string) (AuditLogPage, error) {
	if err := s.authorize(ctx, actorUserID, permAuditRead); err != nil {
		return AuditLogPage{}, err
	}

	requestedLimit := filter.Limit
	if requestedLimit <= 0 || requestedLimit > 100 {
		requestedLimit = 20
	}
	fetchFilter := filter
	fetchFilter.Limit = requestedLimit + 1

	entries, err := s.repo.List(ctx, organizationID, fetchFilter)
	if err != nil {
		return AuditLogPage{}, err
	}

	countFilter := filter
	countFilter.Cursor, countFilter.Limit = nil, 0
	counts, err := s.repo.CountByResult(ctx, organizationID, countFilter)
	if err != nil {
		return AuditLogPage{}, err
	}

	page := AuditLogPage{Counts: counts}
	if len(entries) > requestedLimit {
		page.HasMore = true
		entries = entries[:requestedLimit]
	}
	if page.HasMore {
		last := entries[len(entries)-1]
		page.NextCursor = util.EncodeCursor(last.OccurredAt, last.ID)
	}
	page.Entries = entries

	s.recordAuditAccess(ctx, actorUserID, organizationID, filter, len(entries), ipAddress)
	return page, nil
}

// GetAuditLog is GET /v1/audit-logs/{id}'s own single-event lookup —
// AuditLogRepository.GetByID already existed (List's own sibling, never
// previously exposed over HTTP); this is the authorization and
// organization-isolation wrapper around it that makes exposing it safe.
// A caller from organization A must never be able to read organization
// B's event merely by guessing/incrementing a numeric ID — reported as
// entity.ErrNotFound (never ErrForbidden) so the lookup itself can't be
// used to confirm a given ID exists at all, the same anti-enumeration
// posture GetSecret/LeaseService.Get already establish for the identical
// cross-tenant-ID-guessing shape.
func (s *AuditService) GetAuditLog(ctx context.Context, actorUserID, organizationID, id string) (*entity.AuditLogEntry, error) {
	if err := s.authorize(ctx, actorUserID, permAuditRead); err != nil {
		return nil, err
	}
	entry, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if entry.OrganizationID == nil || *entry.OrganizationID != organizationID {
		return nil, entity.ErrNotFound
	}
	return entry, nil
}

func (s *AuditService) authorize(ctx context.Context, actorUserID, permission string) error {
	if actorUserID == "" {
		return entity.ErrForbidden
	}
	allowed, err := s.rbac.HasPermission(ctx, actorUserID, permission)
	if err != nil {
		return err
	}
	if !allowed {
		return entity.ErrForbidden
	}
	return nil
}

// recordAuditAccess is best-effort, matching every other audit write in
// this codebase. Metadata records which filters were applied and how
// many rows came back — genuinely useful forensic signal about who was
// looking at what ("did anyone query for every event touching this
// user's account last week") — never the returned rows themselves, which
// would duplicate the very data this event exists to point at, not carry.
func (s *AuditService) recordAuditAccess(ctx context.Context, actorUserID, organizationID string, filter repository.AuditLogFilter, resultCount int, ipAddress string) {
	if s.auditTx == nil {
		return
	}
	metadata := map[string]any{"result_count": resultCount}
	if filter.Action != nil {
		metadata["filter_action"] = *filter.Action
	}
	if filter.ActorID != nil {
		metadata["filter_actor_id"] = *filter.ActorID
	}
	if filter.ResourceType != nil {
		metadata["filter_resource_type"] = *filter.ResourceType
	}
	if filter.ResourceID != nil {
		metadata["filter_resource_id"] = *filter.ResourceID
	}
	if filter.Result != nil {
		metadata["filter_result"] = string(*filter.Result)
	}

	err := s.auditTx(ctx, func(audit repository.AuditLogRepository) error {
		return audit.Append(ctx, &entity.AuditLogEntry{
			OrganizationID: strPtr(organizationID),
			ActorType:      entity.AuditActorUser,
			ActorID:        strPtr(actorUserID),
			Action:         "admin.audit.read",
			ResourceType:   strPtr("audit_log"),
			Result:         entity.AuditResultSuccess,
			IPAddress:      strPtr(ipAddress),
			RequestID:      strPtr(util.RequestIDFromContext(ctx)),
			Metadata:       metadata,
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record admin.audit.read audit event", zap.Error(err))
	}
}
