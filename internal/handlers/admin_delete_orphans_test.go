// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- fakes for the two pre-delete seams ---

// fakeApprovals stands in for workflow's ListPendingTasks.
type fakeApprovals struct {
	mu       sync.Mutex
	items    []userdelete.PendingApproval
	err      error
	askedFor []string
}

func (f *fakeApprovals) ListPendingApprovals(_ context.Context, userID string) ([]userdelete.PendingApproval, error) {
	f.mu.Lock()
	f.askedFor = append(f.askedFor, userID)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

func (f *fakeApprovals) queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.askedFor...)
}

// fakeRevoker stands in for the Kratos admin credential revoke.
type fakeRevoker struct {
	mu     sync.Mutex
	res    kratos.RevokeResult
	err    error
	emails []string
}

func (f *fakeRevoker) RevokeIdentity(_ context.Context, email string) (kratos.RevokeResult, error) {
	f.mu.Lock()
	f.emails = append(f.emails, email)
	f.mu.Unlock()
	if f.err != nil {
		return kratos.RevokeResult{}, f.err
	}
	return f.res, nil
}

func (f *fakeRevoker) revoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.emails...)
}

// revokedOK is the outcome of a successful revoke against a local account.
func revokedOK(id string) kratos.RevokeResult {
	return kratos.RevokeResult{
		IdentityID: id, Found: true, Deactivated: true, SessionsRevoked: true, PasswordRemoved: true,
	}
}

// deleteHandler builds an AdminHandler with every pre-delete seam wired and
// passing, so a test only has to bend the one it is about.
func deleteHandler(s *store.Store, ap *fakeApprovals, rv *fakeRevoker) *handlers.AdminHandler {
	return deleteHandlerWith(s, ap, rv, &fakePurger{})
}

// deleteHandlerWith is deleteHandler with an explicit category-rule purger.
func deleteHandlerWith(s *store.Store, ap *fakeApprovals, rv *fakeRevoker, pg *fakePurger) *handlers.AdminHandler {
	return handlers.NewAdminHandler(s, testAdminAuth()).
		WithApprovalLister(ap).
		WithCredentialRevoker(rv).
		WithCategoryRulePurger(pg)
}

// errInfo pulls the coded ErrorInfo off a gRPC error.
func errInfo(t *testing.T, err error) apperrgrpc.Info {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("not a gRPC status error: %v", err)
	}
	info, ok := apperrgrpc.FromStatus(st)
	if !ok {
		t.Fatalf("status carries no coded ErrorInfo: %v", err)
	}
	return info
}

// tombstoned reports whether the user row has been soft-deleted.
func tombstoned(t *testing.T, s *store.Store, id uuid.UUID) bool {
	t.Helper()
	u, err := s.GetUser(context.Background(), id)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	// DeleteUser is the only path that disables an account it also stamps
	// deleted_at on; these tests never disable a user any other way.
	return !u.Enabled
}

// countAudit returns how many pending audit events of eventType target userID.
func countAudit(t *testing.T, s *store.Store, eventType string, userID uuid.UUID) int {
	t.Helper()
	events, err := s.PendingAuditEvents(context.Background(), 500)
	if err != nil {
		t.Fatalf("PendingAuditEvents: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.EventType == eventType && e.TargetUserID != nil && *e.TargetUserID == userID {
			n++
		}
	}
	return n
}

// auditPayload returns the payload of the newest pending audit event of eventType
// for userID.
func auditPayload(t *testing.T, s *store.Store, eventType string, userID uuid.UUID) map[string]any {
	t.Helper()
	events, err := s.PendingAuditEvents(context.Background(), 500)
	if err != nil {
		t.Fatalf("PendingAuditEvents: %v", err)
	}
	var out map[string]any
	for _, e := range events {
		if e.EventType == eventType && e.TargetUserID != nil && *e.TargetUserID == userID {
			out = e.Payload
		}
	}
	if out == nil {
		t.Fatalf("no %s audit event for user %s", eventType, userID)
	}
	return out
}

// TestDeleteUserRefusesWhilePendingApprovalsExist is the headline
// case, reproduced from prod: the account is the assigned approver on two
// PENDING stage-0 seats, each the only assignee on its stage. Deleting it left
// both policies unapprovable by anyone for a month. The delete must now REFUSE
// with a coded, actionable error that NAMES the affected policies, and must
// leave the account (and its credential) completely untouched.
func TestDeleteUserRefusesWhilePendingApprovalsExist(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-o50-admin", "o50admin@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-o50-t1", "erin@partner.example.net", "Erin")

	due := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	ap := &fakeApprovals{items: []userdelete.PendingApproval{
		{TaskID: "4cd05508-7fe7-4a75-8774-58e3a06c259e", PolicyVersionID: "00c14e95-0000-0000-0000-000000000000",
			PolicyTitle: "Artificial Intelligence (AI)", StageIndex: 0, DueAt: due},
		{TaskID: "c2fef161-d252-49f6-9fe4-f8f39d73f545", PolicyVersionID: "2f0a9d95-0000-0000-0000-000000000000",
			PolicyTitle: "Backup and Recovery", StageIndex: 0, DueAt: due},
	}}
	rv := &fakeRevoker{res: revokedOK("kratos-1")}
	h := deleteHandler(s, ap, rv)

	_, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	if err == nil {
		t.Fatal("DeleteUser: got nil error, want a refusal while pending approvals exist")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteUser: got %v (%v), want FailedPrecondition", status.Code(err), err)
	}
	info := errInfo(t, err)
	if info.Symbol != "USER_HAS_PENDING_APPROVALS" || info.Code != 5008 {
		t.Fatalf("coded error: got %s/%d, want USER_HAS_PENDING_APPROVALS/5008", info.Symbol, info.Code)
	}
	if got := info.Metadata["count"]; got != "2" {
		t.Errorf("metadata count: got %q, want \"2\"", got)
	}
	msg := status.Convert(err).Message()
	for _, want := range []string{"Artificial Intelligence (AI)", "Backup and Recovery"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal message must name %q; got %q", want, msg)
		}
		if !strings.Contains(info.Metadata["policies"], want) {
			t.Errorf("metadata policies must name %q; got %q", want, info.Metadata["policies"])
		}
	}

	// The refusal must be complete: nothing tombstoned, nothing revoked.
	if tombstoned(t, s, target.ID) {
		t.Error("a refused delete must not tombstone the account")
	}
	if got := rv.revoked(); len(got) != 0 {
		t.Errorf("a refused delete must not revoke the credential, got %v", got)
	}
	if got := ap.queries(); len(got) != 1 || got[0] != target.ID.String() {
		t.Errorf("approval check queried %v, want exactly [%s]", got, target.ID)
	}
}

// TestDeleteUserRevokesKratosCredential is the security half of:
// the prod delete left the account's Kratos identity state=active with a
// working password credential. A delete must revoke it, and must record the
// real outcome in the audit trail.
func TestDeleteUserRevokesKratosCredential(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-o50-admin2", "o50admin2@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-o50-t2", "local.user@partner.example.net", "Local User")

	ap := &fakeApprovals{}
	rv := &fakeRevoker{res: revokedOK("47feeda5-40bc-47a2-acc9-8a063eebed18")}
	h := deleteHandler(s, ap, rv)

	if _, err := h.DeleteUser(adminCtx(admin.ID.String()),
		&identityv1.DeleteUserRequest{UserId: target.ID.String()}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	got := rv.revoked()
	if len(got) != 1 || got[0] != "local.user@partner.example.net" {
		t.Fatalf("credential revoke called with %v, want [local.user@partner.example.net]", got)
	}
	if !tombstoned(t, s, target.ID) {
		t.Error("the account must be tombstoned after a successful delete")
	}

	// The revoke must be auditable and must say what it actually did.
	if n := countAudit(t, s, "user.credential_revoked", target.ID); n != 1 {
		t.Fatalf("user.credential_revoked audit events: got %d, want 1", n)
	}
	p := auditPayload(t, s, "user.credential_revoked", target.ID)
	for _, k := range []string{"identity_found", "deactivated", "sessions_revoked", "password_removed"} {
		if fmt.Sprint(p[k]) != "true" {
			t.Errorf("audit payload %s: got %v, want true", k, p[k])
		}
	}
	if p["credential_id"] != "47feeda5-40bc-47a2-acc9-8a063eebed18" {
		t.Errorf("audit payload credential_id: got %v", p["credential_id"])
	}
}

// TestDeleteUserFederatedAccountWithNoCredentialSucceeds covers the surviving
// account from note 17494: a federated (SSO-only) account has NO
// Kratos identity at all, so there is no credential to revoke. That is a
// legitimate outcome, not a failure — the delete proceeds and records it.
func TestDeleteUserFederatedAccountWithNoCredentialSucceeds(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-o50-admin3", "o50admin3@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-o50-t3", "erin@example.org", "Erin E")

	rv := &fakeRevoker{res: kratos.RevokeResult{Found: false}}
	h := deleteHandler(s, &fakeApprovals{}, rv)

	if _, err := h.DeleteUser(adminCtx(admin.ID.String()),
		&identityv1.DeleteUserRequest{UserId: target.ID.String()}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if !tombstoned(t, s, target.ID) {
		t.Error("the account must be tombstoned")
	}
	p := auditPayload(t, s, "user.credential_revoked", target.ID)
	if fmt.Sprint(p["identity_found"]) != "false" {
		t.Errorf("audit payload identity_found: got %v, want false", p["identity_found"])
	}
}

// TestDeleteUserRefusesWhenApprovalCheckFails proves the guard fails CLOSED:
// if identity cannot find out whether the account holds pending approvals, it
// refuses instead of deleting blind. Deleting blind is what caused the
// incident.
func TestDeleteUserRefusesWhenApprovalCheckFails(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-o50-admin4", "o50admin4@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-o50-t4", "t4@e", "T4")

	rv := &fakeRevoker{res: revokedOK("kratos-1")}
	h := deleteHandler(s, &fakeApprovals{err: errors.New("workflow unreachable")}, rv)

	_, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	// FailedPrecondition, not Unavailable: the gateway presenter only relays an
	// originating coded message for a client-facing gRPC code, so Unavailable
	// would reach the admin as "Code 5009: Internal Error" with {step} dropped.
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteUser: got %v (%v), want FailedPrecondition", status.Code(err), err)
	}
	info := errInfo(t, err)
	if info.Symbol != "USER_DELETE_CHECKS_UNAVAILABLE" || info.Code != 5009 {
		t.Fatalf("coded error: got %s/%d, want USER_DELETE_CHECKS_UNAVAILABLE/5009", info.Symbol, info.Code)
	}
	if got := info.Metadata["step"]; got != "approval_check" {
		t.Errorf("metadata step: got %q, want \"approval_check\"", got)
	}
	if tombstoned(t, s, target.ID) {
		t.Error("a refused delete must not tombstone the account")
	}
	if got := rv.revoked(); len(got) != 0 {
		t.Errorf("a delete refused at the approval check must not revoke the credential, got %v", got)
	}
}

// TestDeleteUserRefusesWhenCredentialRevokeFails proves the tombstone is never
// written over a credential that is still live — the exact prod state
// reports.
func TestDeleteUserRefusesWhenCredentialRevokeFails(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-o50-admin5", "o50admin5@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-o50-t5", "t5@e", "T5")

	h := deleteHandler(s, &fakeApprovals{}, &fakeRevoker{err: errors.New("kratos unreachable")})

	_, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	// FailedPrecondition, not Unavailable: the gateway presenter only relays an
	// originating coded message for a client-facing gRPC code, so Unavailable
	// would reach the admin as "Code 5009: Internal Error" with {step} dropped.
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteUser: got %v (%v), want FailedPrecondition", status.Code(err), err)
	}
	info := errInfo(t, err)
	if info.Symbol != "USER_DELETE_CHECKS_UNAVAILABLE" {
		t.Fatalf("coded error: got %s, want USER_DELETE_CHECKS_UNAVAILABLE", info.Symbol)
	}
	if got := info.Metadata["step"]; got != "credential_revoke" {
		t.Errorf("metadata step: got %q, want \"credential_revoke\"", got)
	}
	if tombstoned(t, s, target.ID) {
		t.Error("a delete whose credential revoke failed must not tombstone the account")
	}
}

// TestDeleteUserRefusesWhenSeamsNotWired proves an unconfigured deployment
// declines with the same coded error instead of silently skipping the
// mandatory steps — the pre- behaviour.
func TestDeleteUserRefusesWhenSeamsNotWired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-o50-admin6", "o50admin6@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-o50-t6", "t6@e", "T6")

	h := handlers.NewAdminHandler(s, testAdminAuth())

	_, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	// FailedPrecondition, not Unavailable: the gateway presenter only relays an
	// originating coded message for a client-facing gRPC code, so Unavailable
	// would reach the admin as "Code 5009: Internal Error" with {step} dropped.
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteUser: got %v (%v), want FailedPrecondition", status.Code(err), err)
	}
	if info := errInfo(t, err); info.Code != 5009 {
		t.Fatalf("coded error: got %d, want 5009", info.Code)
	}
	if tombstoned(t, s, target.ID) {
		t.Error("an unconfigured deployment must not tombstone the account")
	}
}

// ---: the third pre-delete seam (category-rule purge) --------------

// fakePurger stands in for core's GroupService.PurgeUserCategoryRules.
type fakePurger struct {
	mu     sync.Mutex
	res    userdelete.PurgeResult
	err    error
	asked  []string
	actors []string
}

func (f *fakePurger) PurgeUserCategoryRules(_ context.Context, userID, actorUserID string) (userdelete.PurgeResult, error) {
	f.mu.Lock()
	f.asked = append(f.asked, userID)
	f.actors = append(f.actors, actorUserID)
	f.mu.Unlock()
	if f.err != nil {
		return userdelete.PurgeResult{}, f.err
	}
	return f.res, nil
}

func (f *fakePurger) purged() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

func (f *fakePurger) actorsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.actors...)
}

// TestDeleteUserPurgesOrphanCategoryRules is the headline case,
// reproduced from prod: deleting an account left a user-subject RACI rule
// (subject_kind=user, grant_ack=deny) behind in core.category_rules as dead
// config naming a nonexistent user. The delete must now purge the account's own
// user-subject rules and record what it removed.
func TestDeleteUserPurgesOrphanCategoryRules(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-c43-admin", "c43admin@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-c43-t1", "erin@partner.example.net", "Erin")

	pg := &fakePurger{res: userdelete.PurgeResult{
		RemovedRules:        1,
		AffectedCategoryIDs: []string{"956dc2ab-d9af-44b3-9a38-33e6a87dd49c"},
	}}
	h := deleteHandlerWith(s, &fakeApprovals{}, &fakeRevoker{res: revokedOK("kratos-c43")}, pg)

	if _, err := h.DeleteUser(adminCtx(admin.ID.String()),
		&identityv1.DeleteUserRequest{UserId: target.ID.String()}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got := pg.purged(); len(got) != 1 || got[0] != target.ID.String() {
		t.Fatalf("purge called with %v, want exactly [%s]", got, target.ID)
	}
	if got := pg.actorsSeen(); len(got) != 1 || got[0] != admin.ID.String() {
		t.Fatalf("purge actor: got %v, want [%s] — core attributes the revoke to it", got, admin.ID)
	}
	if !tombstoned(t, s, target.ID) {
		t.Error("the account must be tombstoned after a successful delete")
	}

	// Removing grants IS a permissions change, so identity records its own
	// audit row rather than trusting the removal to be visible only in core.
	if n := countAudit(t, s, "user.category_rules_purged", target.ID); n != 1 {
		t.Fatalf("user.category_rules_purged audit events: got %d, want 1", n)
	}
	p := auditPayload(t, s, "user.category_rules_purged", target.ID)
	if fmt.Sprint(p["removed_rules"]) != "1" {
		t.Errorf("audit payload removed_rules: got %v, want 1", p["removed_rules"])
	}
	if p["reason"] != "user_deleted" {
		t.Errorf("audit payload reason: got %v, want user_deleted", p["reason"])
	}
	if fmt.Sprint(p["affected_category_ids"]) != "[956dc2ab-d9af-44b3-9a38-33e6a87dd49c]" {
		t.Errorf("audit payload affected_category_ids: got %v", p["affected_category_ids"])
	}
}

// TestDeleteUserAuditsAnEmptyPurge proves the zero case is recorded too. Most
// accounts hold no user-subject RACI rules, and "the purge ran and found
// nothing" must be distinguishable from "the purge never ran" — not being able
// to tell those apart is the defect this guards.
func TestDeleteUserAuditsAnEmptyPurge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-c43-admin2", "c43admin2@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-c43-t2", "norules@partner.example.net", "No Rules")

	h := deleteHandlerWith(s, &fakeApprovals{}, &fakeRevoker{res: revokedOK("kratos-c43b")}, &fakePurger{})

	if _, err := h.DeleteUser(adminCtx(admin.ID.String()),
		&identityv1.DeleteUserRequest{UserId: target.ID.String()}); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	p := auditPayload(t, s, "user.category_rules_purged", target.ID)
	if fmt.Sprint(p["removed_rules"]) != "0" {
		t.Errorf("audit payload removed_rules: got %v, want 0", p["removed_rules"])
	}
}

// TestDeleteUserRefusesWhenCategoryRulePurgeFails proves the third step fails
// CLOSED like the other two. A dead grant surfaces as nothing at all — no
// broken page, no stuck workflow — so a best-effort purge would silently
// reproduce the defect it exists to fix.
func TestDeleteUserRefusesWhenCategoryRulePurgeFails(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-c43-admin3", "c43admin3@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-c43-t3", "t3c43@e", "T3")

	h := deleteHandlerWith(s, &fakeApprovals{}, &fakeRevoker{res: revokedOK("kratos-c43c")},
		&fakePurger{err: errors.New("core unreachable")})

	_, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteUser: got %v (%v), want FailedPrecondition", status.Code(err), err)
	}
	info := errInfo(t, err)
	if info.Symbol != "USER_DELETE_CHECKS_UNAVAILABLE" || info.Code != 5009 {
		t.Fatalf("coded error: got %s/%d, want USER_DELETE_CHECKS_UNAVAILABLE/5009", info.Symbol, info.Code)
	}
	if got := info.Metadata["step"]; got != "category_rule_purge" {
		t.Errorf("metadata step: got %q, want \"category_rule_purge\"", got)
	}
	if tombstoned(t, s, target.ID) {
		t.Error("a delete whose category-rule purge failed must not tombstone the account")
	}
}

// TestDeleteUserRefusesWhenPurgerNotWired proves an unconfigured deployment
// (CORE_GRPC_ADDR unset) declines rather than deleting and leaving the grants.
func TestDeleteUserRefusesWhenPurgerNotWired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-c43-admin4", "c43admin4@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-c43-t4", "t4c43@e", "T4")

	h := handlers.NewAdminHandler(s, testAdminAuth()).
		WithApprovalLister(&fakeApprovals{}).
		WithCredentialRevoker(&fakeRevoker{res: revokedOK("kratos-c43d")})

	_, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteUser: got %v (%v), want FailedPrecondition", status.Code(err), err)
	}
	info := errInfo(t, err)
	if info.Code != 5009 {
		t.Fatalf("coded error: got %d, want 5009", info.Code)
	}
	if got := info.Metadata["step"]; got != "category_rule_purge" {
		t.Errorf("metadata step: got %q, want \"category_rule_purge\"", got)
	}
	if tombstoned(t, s, target.ID) {
		t.Error("an unconfigured deployment must not tombstone the account")
	}
}
