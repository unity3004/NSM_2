package http

import (
	"net/http"
	"strconv"
	"time"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/service"
)

// auditHandler translates HTTP requests into service.AuditService calls
// and service results back into dto.* JSON — nothing else, the same
// narrow translation-only role every other handler in this package plays.
// It never queries audit_logs itself and never decides who may see it;
// AuditService does both (see that type's own doc comment on why it
// performs its own internal audit:read check rather than trusting
// requirePermission alone).
type auditHandler struct {
	svc *service.AuditService
}

// list implements GET /v1/audit-logs — the objective's own "list audit
// events, filter by actor/event/resource/result/time range, paginate
// results" requirement. Every filter is optional; supplying none returns
// every event for the caller's organization, newest first, one page at a
// time (never unbounded — see dto.AuditLogQuery.Validate's own Limit
// bound and AuditService.ListAuditLogs' own cursor-pagination doc
// comment).
func (h *auditHandler) list(w http.ResponseWriter, r *http.Request) {
	query, parseErrs := parseAuditLogQuery(r)
	if err := parseErrs.Err(); err != nil {
		writeValidationError(w, r, err)
		return
	}
	if err := query.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	page, err := h.svc.ListAuditLogs(r.Context(), actorUserID(r), organizationIDFromRequest(r), auditFilterFromQuery(query), clientIP(r))
	if err != nil {
		writeServiceError(w, r, err)
		return
	}

	out := make([]dto.AuditLogResponse, 0, len(page.Entries))
	for _, e := range page.Entries {
		out = append(out, dto.AuditLogResponseFromEntity(e))
	}
	var nextCursor *string
	if page.NextCursor != "" {
		nextCursor = &page.NextCursor
	}
	writeJSON(w, r, http.StatusOK, struct {
		Data    []dto.AuditLogResponse `json:"data"`
		Page    dto.PageMeta           `json:"page"`
		Summary dto.AuditLogSummary    `json:"summary"`
	}{
		Data: out,
		Page: dto.PageMeta{NextCursor: nextCursor, HasMore: page.HasMore, Limit: query.Limit},
		Summary: dto.AuditLogSummary{
			Total:   page.Counts[entity.AuditResultSuccess] + page.Counts[entity.AuditResultFailure] + page.Counts[entity.AuditResultDenied],
			Success: page.Counts[entity.AuditResultSuccess],
			Failure: page.Counts[entity.AuditResultFailure],
			Denied:  page.Counts[entity.AuditResultDenied],
		},
	})
}

// parseAuditLogQuery reads GET /v1/audit-logs' query string into a
// dto.AuditLogQuery. Malformed values (an unparseable limit, a
// non-RFC3339 timestamp) are reported per-field via the returned
// dto.ValidationErrors, the same 422-with-field-detail shape
// dto.Validate() methods already produce elsewhere — this function
// exists because query-string parsing is an HTTP-boundary concern
// (net/url.Values), not something dto itself should import net/http to
// do. Enum values (actor_type, result) are range-checked by
// AuditLogQuery.Validate itself, called by this handler immediately
// after — not duplicated here.
func parseAuditLogQuery(r *http.Request) (dto.AuditLogQuery, dto.ValidationErrors) {
	q := r.URL.Query()
	var errs dto.ValidationErrors
	query := dto.AuditLogQuery{Limit: 20}

	if v := q.Get("actor_type"); v != "" {
		query.ActorType = &v
	}
	if v := q.Get("actor_id"); v != "" {
		query.ActorID = &v
	}
	if v := q.Get("action"); v != "" {
		query.Action = &v
	}
	if v := q.Get("resource_type"); v != "" {
		query.ResourceType = &v
	}
	if v := q.Get("resource_id"); v != "" {
		query.ResourceID = &v
	}
	if v := q.Get("result"); v != "" {
		query.Result = &v
	}
	if v := q.Get("request_id"); v != "" {
		query.RequestID = &v
	}
	if v := q.Get("cursor"); v != "" {
		query.Cursor = &v
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			errs.Add("limit", "must be an integer")
		} else {
			query.Limit = n
		}
	}
	if v := q.Get("occurred_after"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			errs.Add("occurred_after", "must be an RFC3339 timestamp")
		} else {
			query.OccurredAfter = &t
		}
	}
	if v := q.Get("occurred_before"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			errs.Add("occurred_before", "must be an RFC3339 timestamp")
		} else {
			query.OccurredBefore = &t
		}
	}

	return query, errs
}

// auditFilterFromQuery translates an already-validated dto.AuditLogQuery
// into repository.AuditLogFilter — the enum string-to-typed-pointer
// conversion is safe unchecked here because dto.AuditLogQuery.Validate
// (called by the handler before this) already rejected any ActorType/
// Result value outside the known set.
func auditFilterFromQuery(q dto.AuditLogQuery) repository.AuditLogFilter {
	f := repository.AuditLogFilter{
		ActorID:        q.ActorID,
		Action:         q.Action,
		ResourceType:   q.ResourceType,
		ResourceID:     q.ResourceID,
		RequestID:      q.RequestID,
		OccurredAfter:  q.OccurredAfter,
		OccurredBefore: q.OccurredBefore,
		Cursor:         q.Cursor,
		Limit:          q.Limit,
	}
	if q.ActorType != nil {
		at := entity.AuditActorType(*q.ActorType)
		f.ActorType = &at
	}
	if q.Result != nil {
		res := entity.AuditResult(*q.Result)
		f.Result = &res
	}
	return f
}
