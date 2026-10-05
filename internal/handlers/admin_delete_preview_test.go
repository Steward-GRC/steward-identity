// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- read-only fakes for the preview seams ---

type fakeOwnedPolicies struct {
	items []userdelete.OwnedPolicy
	err   error
}

func (f *fakeOwnedPolicies) ListPoliciesByOwner(_ context.Context, _ string) ([]userdelete.OwnedPolicy, error) {
	return f.items, f.err
}

type fakeRulePreview struct {
	items []userdelete.RaciGrant
	err   error
}

func (f *fakeRulePreview) PreviewUserCategoryRules(_ context.Context, _ string) ([]userdelete.RaciGrant, error) {
	return f.items, f.err
}

type fakeCredFind struct {
	ref userdelete.CredentialRef
	err error
}

func (f *fakeCredFind) FindCredential(_ context.Context, _ string) (userdelete.CredentialRef, error) {
	return f.ref, f.err
}

// previewHandler builds an AdminHandler with all FOUR preview seams wired, so a
// test only has to say which one it is bending. It deliberately does NOT wire
// the mutating WithCredentialRevoker / WithCategoryRulePurger: if the preview
// ever reached for those, every test here would fail closed rather than
// silently revoke a credential.
func previewHandler(t *testing.T, s *store.Store, op *fakeOwnedPolicies, rp *fakeRulePreview, cf *fakeCredFind, ap *fakeApprovals) *handlers.AdminHandler {
	t.Helper()
	return handlers.NewAdminHandler(s, testAdminAuth()).
		WithApprovalLister(ap).
		WithOwnedPolicyLister(op).
		WithCategoryRulePreviewer(rp).
		WithCredentialFinder(cf)
}

// TestPreviewUserDeletionHappyPath walks one account through the whole RPC and
// asserts the shape an admin dialog needs: per-class counts, reviewable items,
// warnings, and nothing mutated.
func TestPreviewUserDeletionHappyPath(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-prev-a1", "preva1@e", "Admin")
	target, err := s.PreCreateLocalUser(ctx, "prevtarget", "target@prev.example.org", "Target Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	if _, err := s.GrantRole(ctx, target.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if _, err := s.SetPolicyOverride(ctx, target.ID, "IT-001", "deny", nil, "test"); err != nil {
		t.Fatalf("SetPolicyOverride: %v", err)
	}
	// Two break-glass grants on the SAME policy, one already expired. The count
	// must be the raw 2, not ActiveBreakGlass's de-duplicated 1 — the delete
	// removes rows, store.UserAccessRowCounts).
	if _, err := s.GrantBreakGlass(ctx, target.ID, "IT-002", "live", 60, nil); err != nil {
		t.Fatalf("GrantBreakGlass: %v", err)
	}
	if _, err := s.GrantBreakGlass(ctx, target.ID, "IT-002", "again", 60, nil); err != nil {
		t.Fatalf("GrantBreakGlass: %v", err)
	}

	op := &fakeOwnedPolicies{items: []userdelete.OwnedPolicy{{ID: "p-1", Number: "IT-001", Title: "Access Control"}}}
	rp := &fakeRulePreview{items: []userdelete.RaciGrant{{CategoryID: "cat-1", Roles: []string{"author"}}}}
	cf := &fakeCredFind{ref: userdelete.CredentialRef{ID: "kr-1", Found: true, State: "active"}}
	ap := &fakeApprovals{}
	h := previewHandler(t, s, op, rp, cf, ap)

	resp, err := h.PreviewUserDeletion(adminCtx(admin.ID.String()),
		&identityv1.PreviewUserDeletionRequest{UserId: target.ID.String()})
	if err != nil {
		t.Fatalf("PreviewUserDeletion: %v", err)
	}
	p := resp.GetPreview()
	if p.GetUserId() != target.ID.String() {
		t.Errorf("user_id = %q, want %s", p.GetUserId(), target.ID)
	}
	if p.GetBlocksDelete() {
		t.Errorf("nothing blocks this delete, warnings=%v", warningCodes(p))
	}
	if !p.GetLocallyAuthenticable() {
		t.Errorf("a local account with a credential must be locally_authenticable")
	}
	c := p.GetCounts()
	if c.GetOwnedPolicies() != 1 {
		t.Errorf("owned_policies = %d, want 1", c.GetOwnedPolicies())
	}
	if c.GetRaciGrants() != 1 {
		t.Errorf("raci_grants = %d, want 1", c.GetRaciGrants())
	}
	if c.GetRoles() != 1 {
		t.Errorf("roles = %d, want 1", c.GetRoles())
	}
	if c.GetPendingApprovals() != 0 {
		t.Errorf("pending_approvals = %d, want 0", c.GetPendingApprovals())
	}
	if c.GetPolicyOverrides() != 1 {
		t.Errorf("policy_overrides = %d, want 1", c.GetPolicyOverrides())
	}
	if c.GetBreakGlassGrants() != 2 {
		t.Errorf("break_glass_grants = %d, want the RAW 2 (ActiveBreakGlass would de-duplicate to 1)", c.GetBreakGlassGrants())
	}
	if len(p.GetItems()) == 0 {
		t.Fatal("the preview must carry reviewable items, not just counts")
	}
	// Every kind that came back must be a real enum value, never UNSPECIFIED —
	// an unmapped kind renders as a blank row in the dialog.
	for _, it := range p.GetItems() {
		if it.GetKind() == identityv1.DeletionItemKind_DELETION_ITEM_KIND_UNSPECIFIED {
			t.Errorf("item has an UNSPECIFIED kind (unmapped): %+v", it)
		}
	}
	if !hasWarningCode(p, "POLICIES_ORPHANED") {
		t.Errorf("want POLICIES_ORPHANED, got %v", warningCodes(p))
	}
	if !hasWarningCode(p, "RACI_GRANTS_REMOVED") {
		t.Errorf("want RACI_GRANTS_REMOVED, got %v", warningCodes(p))
	}

	// Read-only: the target is untouched. This is the whole contract of a dry
	// run, and the reason the mutating seams are not wired above.
	after, err := s.GetUser(ctx, target.ID)
	if err != nil {
		t.Fatalf("GetUser after preview: %v", err)
	}
	if after.DeletedAt != nil {
		t.Errorf("the preview tombstoned the account")
	}
	if !after.Enabled {
		t.Errorf("the preview disabled the account")
	}
	if len(after.Roles) != 1 {
		t.Errorf("the preview dropped the account's roles: %v", after.Roles)
	}
}

// TestPreviewUserDeletionReportsBlockingApprovals: the class turned
// into a refusal must be visible BEFORE the admin clicks delete, and marked as
// the thing that has to be dealt with first.
func TestPreviewUserDeletionReportsBlockingApprovals(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-prev-a2", "preva2@e", "Admin")
	target, err := s.PreCreateLocalUser(ctx, "prevblocked", "blocked@prev.example.org", "Blocked")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	ap := &fakeApprovals{items: []userdelete.PendingApproval{
		{TaskID: "t-1", PolicyVersionID: "pv-1", PolicyTitle: "Backup and Recovery",
			StageIndex: 0, DueAt: time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)},
	}}
	h := previewHandler(t, s, &fakeOwnedPolicies{}, &fakeRulePreview{}, &fakeCredFind{}, ap)

	resp, err := h.PreviewUserDeletion(adminCtx(admin.ID.String()),
		&identityv1.PreviewUserDeletionRequest{UserId: target.ID.String()})
	if err != nil {
		t.Fatalf("PreviewUserDeletion: %v", err)
	}
	p := resp.GetPreview()
	if !p.GetBlocksDelete() {
		t.Errorf("a pending approval seat must set blocks_delete — DeleteUser will refuse")
	}
	if p.GetCounts().GetPendingApprovals() != 1 {
		t.Errorf("pending_approvals = %d, want 1", p.GetCounts().GetPendingApprovals())
	}
	var blocking int
	for _, it := range p.GetItems() {
		if it.GetBlocksDelete() {
			blocking++
			if it.GetKind() != identityv1.DeletionItemKind_DELETION_ITEM_KIND_PENDING_APPROVAL {
				t.Errorf("only a pending approval blocks, got kind %v", it.GetKind())
			}
			if !strings.Contains(it.GetDetail(), "2026-08-13") {
				t.Errorf("the blocking item must name the SLA date, got %q", it.GetDetail())
			}
		}
	}
	if blocking != 1 {
		t.Errorf("want exactly 1 blocking item, got %d", blocking)
	}
	if !hasWarningCode(p, "DELETE_BLOCKED_PENDING_APPROVALS") {
		t.Errorf("want DELETE_BLOCKED_PENDING_APPROVALS, got %v", warningCodes(p))
	}
}

// TestPreviewUserDeletionFailsClosed pins that an unreadable class is a coded
// REFUSAL naming the step, not a preview with that class quietly missing. It
// reuses errcodes 5009 (USER_DELETE_CHECKS_UNAVAILABLE) — same code and same
// {step} metadata as the delete path, because it is the same condition.
func TestPreviewUserDeletionFailsClosed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-prev-a3", "preva3@e", "Admin")
	target, err := s.PreCreateLocalUser(ctx, "prevfail", "fail@prev.example.org", "Fail")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	boom := errors.New("backend down")

	for _, tc := range []struct {
		name     string
		wantStep string
		build    func() *handlers.AdminHandler
	}{
		{"workflow unreachable", "approval_check", func() *handlers.AdminHandler {
			return previewHandler(t, s, &fakeOwnedPolicies{}, &fakeRulePreview{}, &fakeCredFind{},
				&fakeApprovals{err: boom})
		}},
		{"core policy unreachable", "owned_policies", func() *handlers.AdminHandler {
			return previewHandler(t, s, &fakeOwnedPolicies{err: boom}, &fakeRulePreview{}, &fakeCredFind{},
				&fakeApprovals{})
		}},
		{"core dry run unreachable", "category_rule_purge", func() *handlers.AdminHandler {
			return previewHandler(t, s, &fakeOwnedPolicies{}, &fakeRulePreview{err: boom}, &fakeCredFind{},
				&fakeApprovals{})
		}},
		{"credential store unreachable", "credential_lookup", func() *handlers.AdminHandler {
			return previewHandler(t, s, &fakeOwnedPolicies{}, &fakeRulePreview{}, &fakeCredFind{err: boom},
				&fakeApprovals{})
		}},
		{"core policy client unwired", "owned_policies", func() *handlers.AdminHandler {
			return handlers.NewAdminHandler(s, testAdminAuth()).
				WithApprovalLister(&fakeApprovals{}).
				WithCategoryRulePreviewer(&fakeRulePreview{}).
				WithCredentialFinder(&fakeCredFind{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.build().PreviewUserDeletion(adminCtx(admin.ID.String()),
				&identityv1.PreviewUserDeletionRequest{UserId: target.ID.String()})
			if err == nil {
				t.Fatalf("an unreadable class must REFUSE, got a preview")
			}
			// FailedPrecondition, not Unavailable: the gateway presenter relays an
			// originating coded message only for a client-facing gRPC code.
			if got := status.Code(err); got != codes.FailedPrecondition {
				t.Errorf("gRPC code = %v, want FailedPrecondition", got)
			}
			info := errInfo(t, err)
			if info.Symbol != "USER_DELETE_CHECKS_UNAVAILABLE" {
				t.Errorf("symbol = %q, want USER_DELETE_CHECKS_UNAVAILABLE (reused, not a new code)", info.Symbol)
			}
			if info.Code != 5009 {
				t.Errorf("codeNum = %d, want 5009 — reused with a distinguishing {step}, not a new code", info.Code)
			}
			if info.Domain != "identity" {
				t.Errorf("domain = %q, want identity", info.Domain)
			}
			if info.Metadata["step"] != tc.wantStep {
				t.Errorf("step = %q, want %q — the operator must be told which backend to look at",
					info.Metadata["step"], tc.wantStep)
			}
		})
	}
}

// TestPreviewUserDeletionRootAndTombstoned covers the two account states that
// need saying out loud rather than erroring.
func TestPreviewUserDeletionRootAndTombstoned(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-prev-a4", "preva4@e", "Admin")
	h := previewHandler(t, s, &fakeOwnedPolicies{}, &fakeRulePreview{}, &fakeCredFind{}, &fakeApprovals{})

	t.Run("root is blocked, not errored", func(t *testing.T) {
		root, err := s.PreCreateLocalUserRoot(ctx, "prevroot", "root@prev.example.org", "Root")
		if err != nil {
			t.Fatalf("PreCreateLocalUserRoot: %v", err)
		}
		resp, err := h.PreviewUserDeletion(adminCtx(admin.ID.String()),
			&identityv1.PreviewUserDeletionRequest{UserId: root.ID.String()})
		if err != nil {
			t.Fatalf("previewing root must report rather than error: %v", err)
		}
		if !resp.GetPreview().GetBlocksDelete() {
			t.Errorf("root must set blocks_delete — DeleteUser refuses it outright")
		}
		if !hasWarningCode(resp.GetPreview(), "DELETE_BLOCKED_ROOT_PROTECTED") {
			t.Errorf("want DELETE_BLOCKED_ROOT_PROTECTED, got %v", warningCodes(resp.GetPreview()))
		}
	})

	t.Run("already-deleted account reports its tombstone", func(t *testing.T) {
		dead, err := s.PreCreateLocalUser(ctx, "prevdead", "dead@prev.example.org", "Gone")
		if err != nil {
			t.Fatalf("PreCreateLocalUser: %v", err)
		}
		if _, err := s.DeleteUser(ctx, dead.ID, nil, "test"); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		resp, err := h.PreviewUserDeletion(adminCtx(admin.ID.String()),
			&identityv1.PreviewUserDeletionRequest{UserId: dead.ID.String()})
		if err != nil {
			t.Fatalf("previewing an already-deleted account must not error: %v", err)
		}
		if !hasWarningCode(resp.GetPreview(), "ALREADY_DELETED") {
			t.Errorf("want ALREADY_DELETED, got %v", warningCodes(resp.GetPreview()))
		}
	})
}

// TestPreviewUserDeletionArgumentsAndAuthz pins the gate and the arg handling.
func TestPreviewUserDeletionArgumentsAndAuthz(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-prev-a5", "preva5@e", "Admin")
	h := previewHandler(t, s, &fakeOwnedPolicies{}, &fakeRulePreview{}, &fakeCredFind{}, &fakeApprovals{})

	// Unauthenticated / non-admin context: the admin gate must fire before any
	// backend is touched.
	if _, err := h.PreviewUserDeletion(context.Background(),
		&identityv1.PreviewUserDeletionRequest{UserId: admin.ID.String()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("unauthorized preview: got %v, want PermissionDenied", err)
	}
	if _, err := h.PreviewUserDeletion(adminCtx(admin.ID.String()),
		&identityv1.PreviewUserDeletionRequest{UserId: ""}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty user_id: got %v, want InvalidArgument", err)
	}
	if _, err := h.PreviewUserDeletion(adminCtx(admin.ID.String()),
		&identityv1.PreviewUserDeletionRequest{UserId: "not-a-uuid"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("malformed user_id: got %v, want InvalidArgument", err)
	}
	if _, err := h.PreviewUserDeletion(adminCtx(admin.ID.String()),
		&identityv1.PreviewUserDeletionRequest{UserId: "00000000-0000-0000-0000-000000000000"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown user: got %v, want NotFound", err)
	}
}

func warningCodes(p *identityv1.UserDeletionPreview) []string {
	out := make([]string, 0, len(p.GetWarnings()))
	for _, w := range p.GetWarnings() {
		out = append(out, w.GetCode())
	}
	return out
}

func hasWarningCode(p *identityv1.UserDeletionPreview, code string) bool {
	for _, w := range p.GetWarnings() {
		if w.GetCode() == code {
			return true
		}
	}
	return false
}
