// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"

	"github.com/Bugs5382/go-log"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
)

// WithApprovalLister wires the workflow-backed outstanding-approval reader used
// by the DeleteUser pre-delete guard. Nil leaves DeleteUser
// REFUSING with errcodes.UserDeleteChecksUnavailable rather than deleting
// blind; returns the handler for chaining, mirroring WithMerge.
func (h *AdminHandler) WithApprovalLister(l userdelete.ApprovalLister) *AdminHandler {
	h.approvals = l
	return h
}

// WithCredentialRevoker wires the credential-store client used by the DeleteUser
// pre-delete guard to revoke a deleted account's local-login credential
// . Nil leaves DeleteUser REFUSING with
// errcodes.UserDeleteChecksUnavailable rather than tombstoning an account whose
// password still works; returns the handler for chaining.
func (h *AdminHandler) WithCredentialRevoker(r userdelete.CredentialRevoker) *AdminHandler {
	h.credentials = r
	return h
}

// WithCategoryRulePurger wires the core-backed purge of the deleted account's
// own user-subject category RACI rules. Nil leaves DeleteUser
// REFUSING with errcodes.UserDeleteChecksUnavailable rather than tombstoning an
// account that leaves live grants behind; returns the handler for chaining.
func (h *AdminHandler) WithCategoryRulePurger(p userdelete.CategoryRulePurger) *AdminHandler {
	h.categoryRules = p
	return h
}

// preDeleteGuard runs the mandatory cross-service pre-delete steps for u and
// translates their outcomes into coded, user-safe errors.
//
// It is deliberately NOT a best-effort cleanup. A non-nil error here means the
// tombstone must not be written:
//
//   - the account is the assigned approver on approvals still awaiting a
//     decision — errcodes.UserHasPendingApprovals (5008, FailedPrecondition),
//     naming the affected policies so the admin can reassign or withdraw them;
//   - a mandatory step could not run at all — errcodes.UserDeleteChecksUnavailable
//     (5009, FailedPrecondition), naming the step so an operator knows which
//     backend to look at. FailedPrecondition, not Unavailable: the gateway
//     presenter relays an originating coded message only for a client-facing
//     gRPC code, so Unavailable would surface to the admin as "Code 5009:
//     Internal Error" with the step metadata dropped.
//
// On success the credential revoke and the category-rule purge have ALREADY
// happened, and each real outcome is recorded as its own audit event
// (`user.credential_revoked`, `user.category_rules_purged`) before the caller
// tombstones the row — so the audit trail says what was revoked and what was
// removed even if the tombstone then fails.
func (h *AdminHandler) preDeleteGuard(ctx context.Context, u store.User, actor adminActor) error {
	res, err := userdelete.Check(ctx, userdelete.Steps{
		Approvals:     h.approvals,
		Credentials:   h.credentials,
		CategoryRules: h.categoryRules,
	}, userdelete.Target{
		UserID:      u.ID.String(),
		Email:       u.Email,
		ActorUserID: actor.ActorUserID,
	})
	if err == nil {
		h.auditCredentialRevoked(ctx, u, actor, res)
		h.auditCategoryRulesPurged(ctx, u, actor, res)
		return nil
	}

	if pending, ok := errors.AsType[*userdelete.PendingApprovalsError](err); ok {
		l := log.Ctx(ctx)
		l.Warn().Str("user_id", u.ID.String()).Int("pending_approvals", len(pending.Items)).
			Msg("delete user: refused — account holds pending approval assignments")
		return errcodes.Error(ctx, errcodes.UserHasPendingApprovals(len(pending.Items), userdelete.DescribeApprovals(pending.Items, 0)))
	}

	if unavailable, ok := errors.AsType[*userdelete.StepUnavailableError](err); ok {
		l := log.Ctx(ctx)
		l.Error().Err(unavailable.Err).Str("user_id", u.ID.String()).Str("step", unavailable.Step).
			Msg("delete user: refused — a mandatory pre-delete step could not be completed")
		return errcodes.Error(ctx, errcodes.UserDeleteChecksUnavailable(unavailable.Step, unavailable.Err))
	}

	// Unreachable today (Check returns only the two typed errors above), but a
	// future step must not degrade into a generic Internal.
	l := log.Ctx(ctx)
	l.Error().Err(err).Str("user_id", u.ID.String()).Msg("delete user: pre-delete guard failed")
	return errcodes.Error(ctx, errcodes.UserDeleteChecksUnavailable("pre_delete", err))
}

// auditCredentialRevoked records what the credential store actually did, as its
// own audit event rather than a field on user.deleted, so the revoke is
// independently attributable (the same reason session.revoked is its own event)
// and survives a later tombstone failure.
//
// revoked=false with found=false is the normal, correct outcome for a federated
// (SSO-only) account: there was no local credential to revoke. Recording it
// explicitly is the point — was caused by nobody being able to tell
// "revoked" from "never attempted".
func (h *AdminHandler) auditCredentialRevoked(ctx context.Context, u store.User, actor adminActor, res userdelete.Result) {
	target := u.ID
	payload := map[string]any{
		"store":            "kratos",
		"reason":           "user_deleted",
		"identity_found":   res.Revoke.Found,
		"deactivated":      res.Revoke.Deactivated,
		"sessions_revoked": res.Revoke.SessionsRevoked,
		"password_removed": res.Revoke.PasswordRemoved,
		"credential_id":    res.Revoke.IdentityID,
		"email":            u.Email,
	}
	if err := h.store.EmitAudit(ctx, store.AuditEvent{
		EventType:     "user.credential_revoked",
		ActorUserID:   actorUUIDPtr(actor),
		ActorExternal: actor.ActorExternal,
		TargetUserID:  &target,
		Payload:       payload,
	}); err != nil {
		// The revoke itself succeeded; losing its audit row must not resurrect a
		// live credential by failing the delete.
		l := log.Ctx(ctx)
		l.Error().Err(err).Str("user_id", u.ID.String()).
			Msg("delete user: credential revoked but its audit event could not be recorded")
	}
}

// auditCategoryRulesPurged records what the category-rule purge actually
// removed, as its own audit event for the same reason the credential revoke has
// one: removing a grant IS a permissions change, and it must be attributable to
// the admin who deleted the account rather than inferable only from core.
//
// It is emitted even when removed_rules is 0. Most accounts hold no
// user-subject RACI rules, and "the purge ran and found nothing" has to be
// distinguishable from "the purge never ran" — not being able to tell those
// apart is the defect this guards. core emits its own per-grant
// category_rule.deleted events; this row is identity's record that the step
// happened as part of THIS delete.
func (h *AdminHandler) auditCategoryRulesPurged(ctx context.Context, u store.User, actor adminActor, res userdelete.Result) {
	target := u.ID
	cats := res.Purge.AffectedCategoryIDs
	if cats == nil {
		cats = []string{}
	}
	payload := map[string]any{
		"service":               "core",
		"reason":                "user_deleted",
		"removed_rules":         res.Purge.RemovedRules,
		"affected_category_ids": cats,
	}
	if err := h.store.EmitAudit(ctx, store.AuditEvent{
		EventType:     "user.category_rules_purged",
		ActorUserID:   actorUUIDPtr(actor),
		ActorExternal: actor.ActorExternal,
		TargetUserID:  &target,
		Payload:       payload,
	}); err != nil {
		// The purge itself succeeded; losing its audit row must not resurrect
		// the removed grants by failing the delete.
		l := log.Ctx(ctx)
		l.Error().Err(err).Str("user_id", u.ID.String()).
			Msg("delete user: category rules purged but their audit event could not be recorded")
	}
}
