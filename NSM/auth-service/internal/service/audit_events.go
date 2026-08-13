package service

import (
	"context"

	"go.uber.org/zap"

	"github.com/acme/auth-service/internal/entity"
	"github.com/acme/auth-service/internal/logging"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/util"
)

// recordReuseDetectionRevocation is the shared audit-writing tail of
// refresh-token reuse detection (Sprint 4 Task 3) — the strongest signal
// this codebase produces that a credential may have been stolen, per both
// call sites' own comments. AuthService.RefreshToken (the legacy
// POST /auth/token/refresh flow) and RefreshTokenService.Refresh (the
// Milestone 5B flow) each independently detect reuse and revoke the same
// two things — the refresh-token family and the session — so this is the
// one place either writes what happened, rather than two independent
// implementations that could drift apart or disagree about the shape of
// a reuse-detection event.
//
// Before this task, reuse detection was only visible in the audit trail
// as failure_reason="reuse_detected" metadata buried inside the generic
// auth.token_refresh failure row that flow's own recordRefreshAudit
// always writes — true, but not something an admin reconstructing an
// incident could filter on directly ("show me every forced revocation"
// required already knowing to look inside every token-refresh failure's
// metadata). This adds two first-class rows instead, on top of (not
// replacing) that existing failure entry: session.revoked and
// refresh_token.revoked, each naming its own resource
// (ResourceType/ResourceID) so repository.AuditLogFilter can find either
// directly.
//
// OrganizationID is left unset, matching the existing convention both
// callers' own recordRefreshAudit already follows at this same point in
// the flow (the organization isn't available here without an extra
// lookup neither flow currently makes) — not a new inconsistency this
// function introduces.
func recordReuseDetectionRevocation(ctx context.Context, auditTx AuditTxFunc, userID, sessionID, familyID, ipAddress string) {
	if auditTx == nil {
		return
	}
	requestID := strPtr(util.RequestIDFromContext(ctx))
	err := auditTx(ctx, func(audit repository.AuditLogRepository) error {
		if err := audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    entity.AuditActorUser,
			ActorID:      strPtr(userID),
			Action:       "session.revoked",
			ResourceType: strPtr("session"),
			ResourceID:   strPtr(sessionID),
			Result:       entity.AuditResultSuccess,
			IPAddress:    strPtr(ipAddress),
			RequestID:    requestID,
			Metadata:     map[string]any{"reason": "reuse_detected"},
		}); err != nil {
			return err
		}
		return audit.Append(ctx, &entity.AuditLogEntry{
			ActorType:    entity.AuditActorUser,
			ActorID:      strPtr(userID),
			Action:       "refresh_token.revoked",
			ResourceType: strPtr("refresh_token_family"),
			ResourceID:   strPtr(familyID),
			Result:       entity.AuditResultSuccess,
			IPAddress:    strPtr(ipAddress),
			RequestID:    requestID,
			Metadata:     map[string]any{"reason": "reuse_detected"},
		})
	})
	if err != nil {
		logging.FromContext(ctx).Error("failed to record reuse-detection revocation audit events", zap.Error(err))
	}
}
