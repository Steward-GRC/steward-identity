// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"time"

	"errors"

	"github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/merge"
	"github.com/Steward-GRC/steward-identity/internal/safecast"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// validRevokeReasons is the vocabulary a session revoke records in its
// audit event.
var validRevokeReasons = map[string]bool{
	"logout":          true,
	"admin_logout":    true,
	"user_logout_all": true,
	"disabled":        true,
	"deleted":         true,
	"merged":          true,
}

// revokeReasonOr returns r when it is a known reason, else def.
func revokeReasonOr(r, def string) string {
	if validRevokeReasons[r] {
		return r
	}
	return def
}

// sessionsToProto maps Kratos sessions to the wire form for one user.
func sessionsToProto(userID string, sessions []kratos.Session) []*identityv1.Session {
	out := make([]*identityv1.Session, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, &identityv1.Session{
			SessionId:       s.ID,
			UserId:          userID,
			IssuedAt:        rfc3339(s.IssuedAt),
			AuthenticatedAt: rfc3339(s.AuthenticatedAt),
			ExpiresAt:       rfc3339(s.ExpiresAt),
			Active:          s.Active,
			UserAgent:       s.UserAgent,
			ClientIp:        s.ClientIP,
		})
	}
	return out
}

// defaultBreakGlassDurationMin is the fallback break-glass window (minutes)
// used when BreakGlassDurationMin is left at its zero value.
const defaultBreakGlassDurationMin = 15

// AdminHandler implements IdentityAdminService.
type AdminHandler struct {
	identityv1.UnimplementedIdentityAdminServiceServer
	store *store.Store
	auth  *AdminAuth
	// accounts is the Kratos admin API: local accounts, passwords and
	// sessions. Nil answers the coded "unavailable" errors.
	accounts localAccounts

	// otp wires the step-up email-OTP flow (RequestStepUpOtp + TransferRoot
	// verification). Nil when unwired; RequestStepUpOtp then returns Unavailable
	// and TransferRoot rejects every code (fail-closed).
	otp *otpDeps

	// BreakGlassDurationMin is the break-glass reveal window in minutes; when 0
	// defaultBreakGlassDurationMin (15) is used. Wired from config by main.
	BreakGlassDurationMin int

	// membershipPub publishes membership.changed events on the "jobs" exchange so
	// the obligations service can purge acks a user no longer owes after leaving a
	// group. Nil unless wired via WithMembershipPublisher → emission skipped.
	membershipPub membershipPublisher

	// ssoEvents publishes sso.lifecycle events (e.g. sso.access_granted) so
	// the obligations service can email a user once an admin grants them a group or
	// role. Nil unless wired via WithSSOEventPublisher → emission skipped.
	ssoEvents ssoEventPublisher

	// acctCreatedPub publishes account.created events on the "jobs" exchange so
	// the obligations service sends the welcome-account email when CreateLocalUser
	// provisions a new local account. Nil unless wired via
	// WithAccountCreatedPublisher → emission skipped.
	acctCreatedPub accountCreatedPublisher

	// merge orchestrates the admin account-merge: it drives the
	// core policy/RACI reassign + the obligations service ack transfer + local
	// prefs/session/tombstone steps. Nil unless wired via WithMerge → the
	// PreviewAccountMerge / MergeAccounts RPCs return Unavailable (fail-closed).
	merge mergeOrchestrator

	// approvals reads the account's outstanding workflow approval seats so
	// DeleteUser can REFUSE rather than strand them. Nil unless
	// wired via WithApprovalLister → DeleteUser declines with
	// errcodes.UserDeleteChecksUnavailable instead of deleting blind.
	approvals userdelete.ApprovalLister

	// credentials revokes a deleted account's local-login credential in the
	// credential store (Ory Kratos) before the tombstone is written
	//. Nil unless wired via WithCredentialRevoker → DeleteUser
	// declines with errcodes.UserDeleteChecksUnavailable rather than tombstoning
	// an account whose password still works.
	credentials userdelete.CredentialRevoker

	// categoryRules removes the deleted account's own user-subject category
	// RACI rules in core. Nil unless wired via
	// WithCategoryRulePurger → DeleteUser declines with
	// errcodes.UserDeleteChecksUnavailable rather than tombstoning an account
	// whose grants stay behind as dead config naming a nonexistent user.
	categoryRules userdelete.CategoryRulePurger

	// The three READ-ONLY seams the delete PREVIEW drives. They
	// are separate fields from approvals/credentials/categoryRules above because
	// two of those three MUTATE — the credential revoke deactivates the Kratos
	// identity and drops its password, and the purger deletes rows — so a
	// preview must not reach for them. approvals is the one that IS reused: it
	// was already read-only, which is why the refusal could be built on it.
	//
	// Nil unless wired → PreviewUserDeletion declines with
	// errcodes.UserDeleteChecksUnavailable naming the step, rather than showing
	// an admin a preview that silently omits a class.
	ownedPolicies    userdelete.OwnedPolicyLister
	categoryRulePrev userdelete.CategoryRulePreviewer
	credentialFinder userdelete.CredentialFinder
}

// WithSignIn wires the Kratos admin API.
func (h *AdminHandler) WithSignIn(k localAccounts) *AdminHandler {
	h.accounts = k
	return h
}

// mergeOrchestrator is the account-merge surface the admin handler depends on
// (implemented by *merge.Orchestrator). Kept as an interface so the RPC handlers
// are unit-testable with a fake and the handler stays decoupled from the merge
// package's downstream gRPC clients.
type mergeOrchestrator interface {
	Preview(ctx context.Context, sourceID, targetID string) (*merge.Preview, error)
	Execute(ctx context.Context, sourceID, targetID, actorUserID, actorExternal string, confirmPrivileged bool, idempotencyKey string) (*merge.Result, error)
}

// WithMerge wires the account-merge orchestrator onto the admin handler. Nil
// leaves the merge RPCs returning Unavailable; returns the handler for chaining.
func (h *AdminHandler) WithMerge(m mergeOrchestrator) *AdminHandler {
	h.merge = m
	return h
}

// WithAccountCreatedPublisher wires the "account.created" event publisher so
// CreateLocalUser emits an account-created signal on a fresh local-account
// create. Nil skips emission; returns the handler for chaining, mirroring
// WithMembershipPublisher.
func (h *AdminHandler) WithAccountCreatedPublisher(p accountCreatedPublisher) *AdminHandler {
	h.acctCreatedPub = p
	return h
}

// WithSSOEventPublisher wires the "sso.lifecycle" event publisher so admin
// grant RPCs (AddUserToGroup, GrantRole) emit sso.access_granted on a real
// (membership-changing) grant. Nil skips emission; returns the handler for
// chaining, mirroring WithMembershipPublisher.
func (h *AdminHandler) WithSSOEventPublisher(p ssoEventPublisher) *AdminHandler {
	h.ssoEvents = p
	return h
}

// WithOTP wires the step-up OTP dependencies onto the admin handler (mirrors
// ReadHandler.WithOTP). sender may be nil to run over dev-echo alone in local
// testing; in prod a real Sender must be supplied.
func (h *AdminHandler) WithOTP(sender mailSender, log zerolog.Logger, devEcho bool) *AdminHandler {
	h.otp = &otpDeps{sender: sender, log: log, devEcho: devEcho}
	return h
}

// NewAdminHandler returns an IdentityAdminService on s, gated by auth.
func NewAdminHandler(s *store.Store, auth *AdminAuth) *AdminHandler {
	return &AdminHandler{store: s, auth: auth}
}

// breakGlassDuration returns the configured break-glass window in minutes,
// falling back to the default when unset.
func (h *AdminHandler) breakGlassDuration() int {
	if h.BreakGlassDurationMin > 0 {
		return h.BreakGlassDurationMin
	}
	return defaultBreakGlassDurationMin
}

// actorUUIDPtr converts the string user id on adminActor into a *uuid.UUID
// suitable for store calls. Returns nil if the actor is from the admin CLI path
// (where ActorUserID is empty by design).
func actorUUIDPtr(a adminActor) *uuid.UUID {
	if a.ActorUserID == "" {
		return nil
	}
	id, err := uuid.Parse(a.ActorUserID)
	if err != nil {
		return nil
	}
	return &id
}

// authorizeMembership authorizes a group-membership add/remove on gid
// . It returns the acting actor and whether that actor is a
// site-admin / admin CLI caller (full rights):
//
//   - site-admin role OR admin CLI mTLS -> siteAdmin=true, may change ANY
//     membership including IdP-synced ones;
//   - otherwise the caller is admitted ONLY when they hold a LOCAL
//     group-manager grant on THIS group (store.IsGroupManager), with
//     siteAdmin=false — they may add/remove MANUAL memberships only, and the
//     store refuses sync-owned rows (ErrSyncOwned);
//   - any other caller gets the same PermissionDenied AdminAuth.Authorize
//     returns.
//
// Enforcing this here (not just the gateway) keeps identity fail-closed even if
// a caller reaches the admin service directly.
func (h *AdminHandler) authorizeMembership(ctx context.Context, gid uuid.UUID) (adminActor, bool, error) {
	actor, err := h.auth.Authorize(ctx)
	if err == nil {
		return actor, true, nil
	}
	// Not site-admin or the admin CLI: fall back to the per-group group-manager grant.
	sub, ok := callerSubject(ctx)
	if !ok {
		return adminActor{}, false, err
	}
	uid, perr := uuid.Parse(sub)
	if perr != nil {
		return adminActor{}, false, err
	}
	mgr, merr := h.store.IsGroupManager(ctx, uid, gid)
	if merr != nil {
		return adminActor{}, false, statusFromStoreErr(merr)
	}
	if !mgr {
		return adminActor{}, false, err
	}
	return adminActor{ActorUserID: sub}, false, nil
}

// EnableUser flips users.enabled=true.
func (h *AdminHandler) EnableUser(ctx context.Context, req *identityv1.EnableUserRequest) (*identityv1.EnableUserResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.SetEnabled(ctx, id, true, actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.EnableUserResponse{User: userToProto(u)}, nil
}

// DisableUser flips users.enabled=false and revokes all active sessions.
func (h *AdminHandler) DisableUser(ctx context.Context, req *identityv1.DisableUserRequest) (*identityv1.DisableUserResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.SetEnabled(ctx, id, false, actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	// A disabled user is refused on every request already; ending their
	// sessions is a second lock, so a Kratos outage doesn't fail the disable.
	if h.accounts != nil {
		if n, err := revokeAllSessions(ctx, h.accounts, u); err != nil {
			lg := logger.Ctx(ctx)
			lg.Warn("disable user: session revoke failed", log.F("user_id", id.String()), log.F("error", errText(err)))
		} else {
			h.auditSessionsRevoked(ctx, actor, &id, n, "disabled", "")
		}
	}
	return &identityv1.DisableUserResponse{User: userToProto(u)}, nil
}

// DeleteUser soft-deletes a user without ever deleting a policy.
// The store stamps deleted_at, disables the account, revokes sessions, and drops
// the user's identity-owned access rows; the user's owned policies live in the
// core service and remain (orphaned) for admin re-assignment. The re-assign
// gate ("does this user still own policies?") is enforced upstream at the
// gateway — identity cannot see policies. After a successful delete we emit a
// membership.changed event (best-effort) so the obligations service purges the acks
// the user no longer owes.
//
// — the tombstone is no longer the FIRST thing this RPC does. A
// delete has no target account to move records to (that is MergeAccounts), and
// tombstoning first is what left three classes of live cross-service reference
// dangling in prod. Two mandatory pre-delete steps now run before the row is
// touched (see internal/userdelete for the decision behind each):
//
//  1. outstanding workflow approval seats — the delete is REFUSED
//     (USER_HAS_PENDING_APPROVALS, 5008) and names the affected policies,
//     because a pending seat on a tombstoned account silently makes a policy
//     unapprovable by anyone;
//  2. the account's local-login credential is revoked in the credential store
//     (Ory Kratos) — unconditionally, because there is no reason a deleted
//     account keeps one.
//
// Both fail CLOSED: if either cannot be completed the RPC returns
// USER_DELETE_CHECKS_UNAVAILABLE (5009) and writes NOTHING, mirroring the merge
// orchestrator, which never tombstones a source before its records have moved.
// The order — resolve, root-guard, guard, tombstone — keeps NotFound and
// root-protection answers unchanged and ahead of any cross-service call.
//
// The third class found — orphan user-subject RACI rules in core —
// is handled by the guard's third step since added
// GroupService.PurgeUserCategoryRules (a delete has no target user to move them
// to, so there was previously no RPC that could express the removal). The
// delete preview surfaces that RPC's dry run up front.
func (h *AdminHandler) DeleteUser(ctx context.Context, req *identityv1.DeleteUserRequest) (*identityv1.DeleteUserResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	// Resolve the target first so an unknown user still answers NotFound, and a
	// root account still answers FailedPrecondition, WITHOUT reaching out to
	// workflow or the credential store for an account that cannot be deleted.
	// GetUser deliberately still returns tombstoned rows, so a repeat delete
	// runs the same guard and stays idempotent.
	target, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if target.IsRoot {
		return nil, status.Error(codes.FailedPrecondition, "root protected: cannot delete the root account")
	}
	// The credential revoke below ends every session; count them first so
	// the answer can say how many.
	revoked := h.activeSessionCount(ctx, target)
	if err := h.preDeleteGuard(ctx, target, actor); err != nil {
		return nil, err
	}

	u, err := h.store.DeleteUser(ctx, id, actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	// A deleted user leaves every group/audience — let compliance purge the acks
	// they no longer owe (best-effort; reconcile is idempotent).
	h.emitMembershipChanged(ctx, req.GetUserId())
	return &identityv1.DeleteUserResponse{User: userToProto(u), RevokedSessions: safecast.Int32(revoked)}, nil
}

// RevokeSession revokes one Kratos session.
func (h *AdminHandler) RevokeSession(ctx context.Context, req *identityv1.RevokeSessionRequest) (*identityv1.RevokeSessionResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id required")
	}
	if h.accounts == nil {
		return nil, errcodes.Error(ctx, errcodes.SessionRevokeUnavailable(errNoSignIn))
	}
	revoked, err := h.accounts.RevokeSession(ctx, req.GetSessionId())
	if err != nil {
		return nil, errcodes.Error(ctx, errcodes.SessionRevokeUnavailable(err))
	}
	if !revoked {
		return &identityv1.RevokeSessionResponse{}, nil
	}
	h.auditSessionsRevoked(ctx, actor, nil, 1, revokeReasonOr(req.GetReason(), "admin_logout"), req.GetSessionId())
	return &identityv1.RevokeSessionResponse{Revoked: 1}, nil
}

// RevokeUserSessions revokes every Kratos session of a user. It fails
// closed: when Kratos can't be reached nothing is reported as revoked.
func (h *AdminHandler) RevokeUserSessions(ctx context.Context, req *identityv1.RevokeUserSessionsRequest) (*identityv1.RevokeUserSessionsResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	n, err := revokeAllSessions(ctx, h.accounts, u)
	if err != nil {
		return nil, err
	}
	h.auditSessionsRevoked(ctx, actor, &id, n, revokeReasonOr(req.GetReason(), "admin_logout"), "")
	return &identityv1.RevokeUserSessionsResponse{Revoked: safecast.Int32(n)}, nil
}

// ListUserSessions lists a user's Kratos sessions. When Kratos can't answer
// it says so, rather than returning an empty list that reads as "signed in
// nowhere".
func (h *AdminHandler) ListUserSessions(ctx context.Context, req *identityv1.ListUserSessionsRequest) (*identityv1.ListUserSessionsResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	if h.accounts == nil {
		return nil, errcodes.Error(ctx, errcodes.SessionsUnavailable(errNoSignIn))
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	identityID, found, err := kratosIdentityID(ctx, h.accounts, u)
	if err != nil {
		return nil, errcodes.Error(ctx, errcodes.SessionsUnavailable(err))
	}
	if !found {
		return &identityv1.ListUserSessionsResponse{}, nil
	}
	sessions, err := h.accounts.ListSessions(ctx, identityID)
	if err != nil {
		return nil, errcodes.Error(ctx, errcodes.SessionsUnavailable(err))
	}
	return &identityv1.ListUserSessionsResponse{Sessions: sessionsToProto(id.String(), sessions)}, nil
}

// RevokeAccountSessions ends every Kratos session of an account and records
// it; the merge saga's session step runs through it.
func (h *AdminHandler) RevokeAccountSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	u, err := h.store.GetUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	n, err := revokeAllSessions(ctx, h.accounts, u)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		h.auditSessionsRevoked(ctx, callerAdminActor(ctx), &userID, n, "merged", "")
	}
	return n, nil
}

// callerAdminActor is the forwarded actor as an adminActor, for audit
// written outside an RPC's own authorization.
func callerAdminActor(ctx context.Context) adminActor {
	if sub, ok := callerSubject(ctx); ok {
		return adminActor{ActorUserID: sub}
	}
	return adminActor{}
}

// activeSessionCount counts u's active Kratos sessions; 0 when there's no
// Kratos or it can't answer.
func (h *AdminHandler) activeSessionCount(ctx context.Context, u store.User) int {
	if h.accounts == nil {
		return 0
	}
	id, found, err := kratosIdentityID(ctx, h.accounts, u)
	if err != nil || !found {
		return 0
	}
	sessions, err := h.accounts.ListSessions(ctx, id)
	if err != nil {
		return 0
	}
	n := 0
	for _, s := range sessions {
		if s.Active {
			n++
		}
	}
	return n
}

// auditSessionsRevoked records a session revoke. A failed write is logged:
// the sessions are already gone.
func (h *AdminHandler) auditSessionsRevoked(ctx context.Context, actor adminActor, target *uuid.UUID, n int, reason, sessionID string) {
	payload := map[string]any{"reason": reason, "revoked": n}
	if sessionID != "" {
		payload["session_id"] = sessionID
	}
	if err := h.store.EmitAudit(ctx, store.AuditEvent{
		EventType: "session.revoked", ActorUserID: actorUUIDPtr(actor), ActorExternal: actor.ActorExternal,
		TargetUserID: target, Payload: payload,
	}); err != nil {
		lg := logger.Ctx(ctx)
		lg.Warn("session revoke: audit write failed", log.F("error", errText(err)))
	}
}

// GrantRole adds a role to a user.
func (h *AdminHandler) GrantRole(ctx context.Context, req *identityv1.GrantRoleRequest) (*identityv1.GrantRoleResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	if req.GetRole() == "" {
		return nil, status.Error(codes.InvalidArgument, "role required")
	}
	// Snapshot the before-state (best-effort) so a genuinely new grant can be
	// told apart from a no-op re-grant of a role the user already holds —
	// store.GrantRole itself is idempotent and doesn't report which case
	// occurred. A lookup failure here just skips the access-granted emit
	// below; it never fails the grant itself.
	before, beforeErr := h.store.GetUser(ctx, id)
	u, err := h.store.GrantRole(ctx, id, req.GetRole(), req.GetCategory(), actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if beforeErr == nil && !hasRole(before, req.GetRole(), req.GetCategory()) {
		h.emitAccessGranted(ctx, id.String(), u.Email, grantDescription(req.GetRole(), req.GetCategory()))
	}
	return &identityv1.GrantRoleResponse{User: userToProto(u)}, nil
}

// RevokeRole removes a role from a user.
func (h *AdminHandler) RevokeRole(ctx context.Context, req *identityv1.RevokeRoleRequest) (*identityv1.RevokeRoleResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	if req.GetRole() == "" {
		return nil, status.Error(codes.InvalidArgument, "role required")
	}
	u, err := h.store.RevokeRole(ctx, id, req.GetRole(), req.GetCategory(), actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.RevokeRoleResponse{User: userToProto(u)}, nil
}

// GrantPermission grants an individual permission to a user. Assigning
// policy.read_sensitive is root-only: beyond the standard admin gate, the
// resolved actor must be the protected root account.
func (h *AdminHandler) GrantPermission(ctx context.Context, req *identityv1.GrantPermissionRequest) (*identityv1.GrantPermissionResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	if err := h.requireRoot(ctx, actor); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	if req.GetPermission() == "" {
		return nil, status.Error(codes.InvalidArgument, "permission required")
	}
	if err := h.store.GrantPermission(ctx, id, req.GetPermission(), actorUUIDPtr(actor), actor.ActorExternal); err != nil {
		return nil, statusFromStoreErr(err)
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.GrantPermissionResponse{User: userToProto(u)}, nil
}

// RevokePermission removes an individual permission from a user (root-only).
func (h *AdminHandler) RevokePermission(ctx context.Context, req *identityv1.RevokePermissionRequest) (*identityv1.RevokePermissionResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	if err := h.requireRoot(ctx, actor); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	if req.GetPermission() == "" {
		return nil, status.Error(codes.InvalidArgument, "permission required")
	}
	if err := h.store.RevokePermission(ctx, id, req.GetPermission(), actorUUIDPtr(actor), actor.ActorExternal); err != nil {
		return nil, statusFromStoreErr(err)
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.RevokePermissionResponse{User: userToProto(u)}, nil
}

// BreakGlassReveal records a time-boxed, audited break-glass reveal for the
// calling site-admin on a single policy. site-admin is the correct gate: only
// site-admins ever see obfuscated content, so only they ever need to break the
// glass. A non-empty reason is mandatory (InvalidArgument otherwise). The grant
// is tied to the calling platform user; the operator/admin CLI path (no platform
// user id) cannot break the glass.
func (h *AdminHandler) BreakGlassReveal(ctx context.Context, req *identityv1.BreakGlassRevealRequest) (*identityv1.BreakGlassRevealResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetPolicyNumber() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_number required")
	}
	if req.GetReason() == "" {
		return nil, status.Error(codes.InvalidArgument, "reason required for break-glass")
	}
	subject := actorUUIDPtr(actor)
	if subject == nil {
		return nil, status.Error(codes.PermissionDenied, "break-glass requires an authenticated platform user")
	}
	exp, err := h.store.GrantBreakGlass(ctx, *subject, req.GetPolicyNumber(), req.GetReason(),
		h.breakGlassDuration(), subject)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.BreakGlassRevealResponse{GrantedUntil: exp.UTC().Format(time.RFC3339)}, nil
}

// ActiveBreakGlass returns the policy numbers for which the calling user holds
// an unexpired break-glass grant. The subject is the calling platform user.
func (h *AdminHandler) ActiveBreakGlass(ctx context.Context, _ *identityv1.ActiveBreakGlassRequest) (*identityv1.ActiveBreakGlassResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	subject := actorUUIDPtr(actor)
	if subject == nil {
		return &identityv1.ActiveBreakGlassResponse{}, nil
	}
	nums, err := h.store.ActiveBreakGlass(ctx, subject.String())
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.ActiveBreakGlassResponse{PolicyNumbers: nums}, nil
}

// requireRoot enforces that the resolved actor is the protected root account.
// The admin CLI operator path (actor with no platform user id) is treated
// as root, since it is the operator break-glass channel.
func (h *AdminHandler) requireRoot(ctx context.Context, actor adminActor) error {
	isRoot, err := h.store.IsRootActor(ctx, actorUUIDPtr(actor))
	if err != nil {
		return statusFromStoreErr(err)
	}
	if !isRoot {
		return errcodes.Error(ctx, errcodes.RootRequired("policy.read_sensitive"))
	}
	return nil
}

// CreateGroup inserts a new group.
func (h *AdminHandler) CreateGroup(ctx context.Context, req *identityv1.CreateGroupRequest) (*identityv1.CreateGroupResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	parent, err := parseOptionalUUID(req.GetParentId(), "parent_id")
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	g, err := h.store.CreateGroup(ctx, req.GetName(), parent, req.GetMetadata(),
		actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.CreateGroupResponse{Group: groupToProto(g)}, nil
}

// RenameGroup updates the display name of a group.
func (h *AdminHandler) RenameGroup(ctx context.Context, req *identityv1.RenameGroupRequest) (*identityv1.RenameGroupResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	if req.GetNewName() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_name required")
	}
	g, err := h.store.RenameGroup(ctx, id, req.GetNewName(),
		actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.RenameGroupResponse{Group: groupToProto(g)}, nil
}

// DeleteGroup removes a group; only succeeds if empty + leaf.
func (h *AdminHandler) DeleteGroup(ctx context.Context, req *identityv1.DeleteGroupRequest) (*identityv1.DeleteGroupResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	if err := h.store.DeleteGroup(ctx, id, actorUUIDPtr(actor), actor.ActorExternal); err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.DeleteGroupResponse{GroupId: req.GetGroupId()}, nil
}

// AddUserToGroup creates a membership row. Site-admins and per-group
// group-managers may both add; a group-manager's grant is always
// MANUAL provenance (source is server-set, never client-supplied).
func (h *AdminHandler) AddUserToGroup(ctx context.Context, req *identityv1.AddUserToGroupRequest) (*identityv1.AddUserToGroupResponse, error) {
	uid, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	gid, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	actor, _, err := h.authorizeMembership(ctx, gid)
	if err != nil {
		return nil, err
	}
	changed, err := h.store.AddUserToGroup(ctx, uid, gid, actorUUIDPtr(actor), actor.ActorExternal, store.SourceManual)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	// Only a real membership change (not a no-op re-grant) should tell the
	// user they now have access — see emitAccessGrantedForGroup for the
	// email/name resolution and vars shape.
	if changed {
		h.emitAccessGrantedForGroup(ctx, uid, gid)
	}
	return &identityv1.AddUserToGroupResponse{UserId: req.GetUserId(), GroupId: req.GetGroupId()}, nil
}

// RemoveUserFromGroup deletes a membership row. Site-admins may remove any
// membership; a per-group group-manager may remove MANUAL
// memberships only — the store refuses IdP-synced rows (ErrSyncOwned) for a
// non-site-admin caller.
func (h *AdminHandler) RemoveUserFromGroup(ctx context.Context, req *identityv1.RemoveUserFromGroupRequest) (*identityv1.RemoveUserFromGroupResponse, error) {
	uid, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	gid, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	actor, siteAdmin, err := h.authorizeMembership(ctx, gid)
	if err != nil {
		return nil, err
	}
	if err := h.store.RemoveUserFromGroup(ctx, uid, gid, actorUUIDPtr(actor), actor.ActorExternal, !siteAdmin); err != nil {
		return nil, statusFromStoreErr(err)
	}
	// Leaving a group can drop the user out of the audience of policies that group
	// was targeted by — let compliance purge the acks they no longer owe.
	h.emitMembershipChanged(ctx, req.GetUserId())
	return &identityv1.RemoveUserFromGroupResponse{UserId: req.GetUserId(), GroupId: req.GetGroupId()}, nil
}

// GrantGroupManager makes a user a LOCAL group-manager of a single group
// . Site-admin gated (the full AdminAuth gate): granting the
// manager role is NOT itself something a group-manager may do — managers only
// manage membership. Idempotent; returns the refreshed user so callers see the
// updated managed_group_ids.
func (h *AdminHandler) GrantGroupManager(ctx context.Context, req *identityv1.GrantGroupManagerRequest) (*identityv1.GrantGroupManagerResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	gid, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	if err := h.store.GrantGroupManager(ctx, uid, gid, actorUUIDPtr(actor), actor.ActorExternal); err != nil {
		return nil, statusFromStoreErr(err)
	}
	u, err := h.store.GetUser(ctx, uid)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.GrantGroupManagerResponse{User: userToProto(u)}, nil
}

// RevokeGroupManager removes a user's group-manager grant on a single group
// . Site-admin gated; idempotent.
func (h *AdminHandler) RevokeGroupManager(ctx context.Context, req *identityv1.RevokeGroupManagerRequest) (*identityv1.RevokeGroupManagerResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	gid, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	if err := h.store.RevokeGroupManager(ctx, uid, gid, actorUUIDPtr(actor), actor.ActorExternal); err != nil {
		return nil, statusFromStoreErr(err)
	}
	u, err := h.store.GetUser(ctx, uid)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.RevokeGroupManagerResponse{User: userToProto(u)}, nil
}

// SetGroupParent re-parents a group.
func (h *AdminHandler) SetGroupParent(ctx context.Context, req *identityv1.SetGroupParentRequest) (*identityv1.SetGroupParentResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	newParent, err := parseOptionalUUID(req.GetNewParentId(), "new_parent_id")
	if err != nil {
		return nil, err
	}
	g, err := h.store.SetGroupParent(ctx, id, newParent, actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.SetGroupParentResponse{Group: groupToProto(g)}, nil
}

// SetUserPolicyOverride sets or clears a per-user allow/deny override for a
// specific policy number. Passing OVERRIDE_EFFECT_UNSPECIFIED clears the override.
func (h *AdminHandler) SetUserPolicyOverride(ctx context.Context, req *identityv1.SetUserPolicyOverrideRequest) (*identityv1.SetUserPolicyOverrideResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	uid, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	if req.GetPolicyNumber() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_number required")
	}
	u, err := h.store.SetPolicyOverride(ctx, uid, req.GetPolicyNumber(), effectFromProto(req.GetEffect()), actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.SetUserPolicyOverrideResponse{User: userToProto(u)}, nil
}

// RequestStepUpOtp mints a step_up OTP for the CALLING admin (actor bound from
// forwarded claims — never from input) and emails it to that actor's own
// address. It arms the server-verified confirmation required by TransferRoot.
// The response is content-free (anti-enumeration), mirroring RequestLoginOtp;
// every real failure is logged server-side only. Only the gateway (claims) path
// can arm this — the admin CLI path has no platform user id to email.
func (h *AdminHandler) RequestStepUpOtp(ctx context.Context, _ *identityv1.RequestStepUpOtpRequest) (*identityv1.RequestStepUpOtpResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if h.otp == nil {
		return nil, status.Error(codes.Unavailable, "otp not configured")
	}
	lg := logger.Ctx(ctx)
	uid := actorUUIDPtr(actor)
	if uid == nil {
		// Toolbox/mTLS actor: no platform user id to email a code to. Nothing to
		// do (generic success keeps the surface uniform).
		lg.Info("step-up otp request from non-gateway actor — no email sent")
		return &identityv1.RequestStepUpOtpResponse{}, nil
	}
	u, err := h.store.GetUser(ctx, *uid)
	if err != nil {
		lg.Warn("step-up otp: actor lookup failed", log.F("user_id", uid.String()), log.F("error", errText(err)))
		return &identityv1.RequestStepUpOtpResponse{}, nil
	}
	code, err := h.store.GenerateOTP(ctx, u.ID, store.OTPPurposeStepUp)
	if err != nil {
		lg.Warn("step-up otp generate failed", log.F("user_id", u.ID.String()), log.F("error", errText(err)))
		return &identityv1.RequestStepUpOtpResponse{}, nil
	}
	if h.otp.devEcho {
		lg.Info("DEV: one-time code (OTP_DEV_ECHO)", log.F("purpose", store.OTPPurposeStepUp), log.F("email", u.Email), log.F("otp_code", code))
	}
	if h.otp.sender != nil && u.Email != "" {
		body := "Use this code to confirm transferring root of Steward:\n\n    " + code +
			"\n\nThis code expires in 10 minutes. If you did not request it, ignore this email."
		if err := h.otp.sender.Send(ctx, u.Email, "Your confirmation code for transferring root", body); err != nil {
			lg.Warn("step-up otp email send failed", log.F("email", u.Email), log.F("error", errText(err)))
		}
	}
	return &identityv1.RequestStepUpOtpResponse{}, nil
}

// TransferRoot moves the protected root site-admin to another user (#19),
// granting the target site-admin + admin and clearing the old root. It is
// gated by a step_up OTP: the code in req.otp is VERIFIED for the acting admin
// (single-use) BEFORE any transfer. A missing/invalid/expired code returns
// InvalidArgument and performs no transfer (fail-closed).
func (h *AdminHandler) TransferRoot(ctx context.Context, req *identityv1.TransferRootRequest) (*identityv1.TransferRootResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetToUserId(), "to_user_id")
	if err != nil {
		return nil, err
	}
	// Server-side step-up check: verify the emailed confirmation code for the
	// ACTING admin before doing anything. The client cannot skip this.
	if err := h.verifyStepUp(ctx, actor, req.GetOtp()); err != nil {
		return nil, err
	}
	u, err := h.store.TransferRoot(ctx, id, actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.TransferRootResponse{User: userToProto(u)}, nil
}

// verifyStepUp consumes a step_up OTP for the acting admin. It fails closed:
// missing OTP, no otp subsystem, no platform user id (admin CLI path), or an
// invalid/expired/used code all return InvalidArgument with a uniform message
// and DO NOT let the caller proceed.
func (h *AdminHandler) verifyStepUp(ctx context.Context, actor adminActor, code string) error {
	const badCode = "invalid or expired confirmation code"
	if code == "" {
		return status.Error(codes.InvalidArgument, badCode)
	}
	if h.otp == nil {
		return status.Error(codes.Unavailable, "otp not configured")
	}
	uid := actorUUIDPtr(actor)
	if uid == nil {
		// Toolbox/mTLS actor has no minted step-up code — refuse.
		return status.Error(codes.InvalidArgument, badCode)
	}
	if err := h.store.VerifyOTP(ctx, *uid, store.OTPPurposeStepUp, code); err != nil {
		if errors.Is(err, store.ErrOTPInvalid) {
			return status.Error(codes.InvalidArgument, badCode)
		}
		return statusFromStoreErr(err)
	}
	return nil
}

// BootstrapInitialAdmin creates the first admin user. Idempotent: subsequent
// calls return the existing admin with created=false.
func (h *AdminHandler) BootstrapInitialAdmin(ctx context.Context, req *identityv1.BootstrapInitialAdminRequest) (*identityv1.BootstrapInitialAdminResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetExternalSubject() == "" || req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "external_subject and email required")
	}
	u, created, err := h.store.BootstrapAdmin(ctx, req.GetExternalSubject(), req.GetEmail(), actor.ActorExternal)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.BootstrapInitialAdminResponse{User: userToProto(u), Created: created}, nil
}
