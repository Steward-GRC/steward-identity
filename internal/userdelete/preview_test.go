// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-identity/internal/userdelete"
)

// — the read-only dry run. These tests use fakes only; no database
// and no network, which is the point of keeping the domain logic out of the
// handler.

type stubOwnedPolicies struct {
	items  []userdelete.OwnedPolicy
	err    error
	asked  []string
	called int
}

func (s *stubOwnedPolicies) ListPoliciesByOwner(_ context.Context, userID string) ([]userdelete.OwnedPolicy, error) {
	s.called++
	s.asked = append(s.asked, userID)
	return s.items, s.err
}

type stubRulePreviewer struct {
	items  []userdelete.RaciGrant
	err    error
	asked  []string
	called int
}

func (s *stubRulePreviewer) PreviewUserCategoryRules(_ context.Context, userID string) ([]userdelete.RaciGrant, error) {
	s.called++
	s.asked = append(s.asked, userID)
	return s.items, s.err
}

type stubCredFinder struct {
	ref    userdelete.CredentialRef
	err    error
	asked  []string
	called int
}

func (s *stubCredFinder) FindCredential(_ context.Context, email string) (userdelete.CredentialRef, error) {
	s.called++
	s.asked = append(s.asked, email)
	return s.ref, s.err
}

// allPreviewSteps wires every seam with a passing stub so a test only has to
// say which one it is bending.
func allPreviewSteps() (userdelete.PreviewSteps, *stubLister, *stubOwnedPolicies, *stubRulePreviewer, *stubCredFinder) {
	l := &stubLister{}
	op := &stubOwnedPolicies{}
	rp := &stubRulePreviewer{}
	cf := &stubCredFinder{}
	return userdelete.PreviewSteps{Approvals: l, OwnedPolicies: op, CategoryRules: rp, Credentials: cf}, l, op, rp, cf
}

func liveAccount() userdelete.Account {
	return userdelete.Account{UserID: "u-1", Email: "person@x.example.org", LocalAccount: true}
}

func warnCodes(p *userdelete.DeletionPreview) []string {
	out := make([]string, 0, len(p.Warnings))
	for _, w := range p.Warnings {
		out = append(out, w.Code)
	}
	return out
}

func hasWarn(p *userdelete.DeletionPreview, code string) bool {
	for _, w := range p.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func itemsOfKind(p *userdelete.DeletionPreview, kind string) []userdelete.DeletionItem {
	var out []userdelete.DeletionItem
	for _, it := range p.Items {
		if it.Kind == kind {
			out = append(out, it)
		}
	}
	return out
}

// TestPreviewFailsClosedOnUnwiredClient is the core safety property. A preview
// is read and ACTED ON, so one that silently omits a class because a backend is
// unwired actively tells the admin that nothing of that kind will be affected —
// which is the defect with extra confidence attached.
func TestPreviewFailsClosedOnUnwiredClient(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wantStep string
		bend     func(*userdelete.PreviewSteps)
	}{
		{"approvals", "approval_check", func(s *userdelete.PreviewSteps) { s.Approvals = nil }},
		{"owned policies", "owned_policies", func(s *userdelete.PreviewSteps) { s.OwnedPolicies = nil }},
		{"category rules", "category_rule_purge", func(s *userdelete.PreviewSteps) { s.CategoryRules = nil }},
		{"credential", "credential_lookup", func(s *userdelete.PreviewSteps) { s.Credentials = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps, _, _, _, _ := allPreviewSteps()
			tc.bend(&steps)
			p, err := userdelete.Preview(context.Background(), steps, liveAccount())
			if err == nil {
				t.Fatalf("an unwired %s client must REFUSE, got a preview: %+v", tc.name, p)
			}
			var su *userdelete.StepUnavailableError
			if !errors.As(err, &su) {
				t.Fatalf("want *StepUnavailableError, got %T: %v", err, err)
			}
			if su.Step != tc.wantStep {
				t.Errorf("step = %q, want %q (the operator is told which backend to look at)", su.Step, tc.wantStep)
			}
		})
	}
}

// TestPreviewFailsClosedOnClientError pins that a FAILING client is refused the
// same way an unwired one is — "the call errored" must not read as "there is
// nothing of this kind".
func TestPreviewFailsClosedOnClientError(t *testing.T) {
	boom := errors.New("backend down")
	for _, tc := range []struct {
		name     string
		wantStep string
		bend     func(*stubLister, *stubOwnedPolicies, *stubRulePreviewer, *stubCredFinder)
	}{
		{"approvals", "approval_check", func(l *stubLister, _ *stubOwnedPolicies, _ *stubRulePreviewer, _ *stubCredFinder) { l.err = boom }},
		{"owned policies", "owned_policies", func(_ *stubLister, o *stubOwnedPolicies, _ *stubRulePreviewer, _ *stubCredFinder) { o.err = boom }},
		{"category rules", "category_rule_purge", func(_ *stubLister, _ *stubOwnedPolicies, r *stubRulePreviewer, _ *stubCredFinder) { r.err = boom }},
		{"credential", "credential_lookup", func(_ *stubLister, _ *stubOwnedPolicies, _ *stubRulePreviewer, c *stubCredFinder) { c.err = boom }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps, l, op, rp, cf := allPreviewSteps()
			tc.bend(l, op, rp, cf)
			_, err := userdelete.Preview(context.Background(), steps, liveAccount())
			var su *userdelete.StepUnavailableError
			if !errors.As(err, &su) {
				t.Fatalf("want *StepUnavailableError, got %T: %v", err, err)
			}
			if su.Step != tc.wantStep {
				t.Errorf("step = %q, want %q", su.Step, tc.wantStep)
			}
			if !errors.Is(err, boom) {
				t.Errorf("the underlying cause must be unwrappable for the operator log")
			}
		})
	}
}

// TestPreviewReportsPendingApprovalsAsBlocking is the class made a
// refusal. The preview's job is to show it BEFORE the admin clicks delete, and
// to mark it as the one class that has to be cleared first.
func TestPreviewReportsPendingApprovalsAsBlocking(t *testing.T) {
	steps, l, _, _, _ := allPreviewSteps()
	due := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	l.items = []userdelete.PendingApproval{
		{TaskID: "t-1", PolicyVersionID: "pv-1", PolicyTitle: "Backup and Recovery", StageIndex: 0, DueAt: due},
		{TaskID: "t-2", PolicyVersionID: "pv-2", StageIndex: 2},
	}

	p, err := userdelete.Preview(context.Background(), steps, liveAccount())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !p.BlocksDelete {
		t.Errorf("a pending approval seat must set BlocksDelete — DeleteUser will refuse")
	}
	if p.Counts.PendingApprovals != 2 {
		t.Errorf("PendingApprovals = %d, want 2", p.Counts.PendingApprovals)
	}
	items := itemsOfKind(p, userdelete.KindPendingApproval)
	if len(items) != 2 {
		t.Fatalf("want 2 pending-approval items, got %d", len(items))
	}
	for _, it := range items {
		if !it.BlocksDelete {
			t.Errorf("every pending-approval item must be marked BlocksDelete: %+v", it)
		}
	}
	// Stage is 1-based for humans, and the SLA date is named.
	if want := "stage 1, due 2026-08-13"; items[0].Detail != want {
		t.Errorf("item detail = %q, want %q", items[0].Detail, want)
	}
	if items[0].Label != "Backup and Recovery" {
		t.Errorf("item label = %q, want the policy title", items[0].Label)
	}
	// A title-less seat must never render as nothing.
	if !strings.Contains(items[1].Label, "pv-2") {
		t.Errorf("a title-less seat must fall back to its version id, got %q", items[1].Label)
	}
	if !hasWarn(p, userdelete.WarnBlockedPendingApprovals) {
		t.Errorf("want %s warning, got %v", userdelete.WarnBlockedPendingApprovals, warnCodes(p))
	}
}

// TestPreviewBlocksRootBeforeCallingAnyBackend: DeleteUser refuses root
// outright, so a preview that described root's blast radius would be describing
// a delete that can never happen.
func TestPreviewBlocksRootProtected(t *testing.T) {
	steps, _, _, _, _ := allPreviewSteps()
	acct := liveAccount()
	acct.IsRoot = true

	p, err := userdelete.Preview(context.Background(), steps, acct)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !p.BlocksDelete {
		t.Errorf("the protected root account must set BlocksDelete")
	}
	if !hasWarn(p, userdelete.WarnBlockedRootProtected) {
		t.Errorf("want %s warning, got %v", userdelete.WarnBlockedRootProtected, warnCodes(p))
	}
}

// TestPreviewOfAlreadyDeletedAccount: previewing a delete of a tombstoned
// account is legitimate (GetUser stays tombstone-blind by design) and must say
// so rather than 404 or pretend the account is live.
func TestPreviewOfAlreadyDeletedAccount(t *testing.T) {
	steps, _, _, _, _ := allPreviewSteps()
	acct := liveAccount()
	acct.DeletedAt = time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	p, err := userdelete.Preview(context.Background(), steps, acct)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !hasWarn(p, userdelete.WarnAlreadyDeleted) {
		t.Fatalf("want %s warning, got %v", userdelete.WarnAlreadyDeleted, warnCodes(p))
	}
	for _, w := range p.Warnings {
		if w.Code == userdelete.WarnAlreadyDeleted && !strings.Contains(w.Message, "2026-09-15") {
			t.Errorf("the ALREADY_DELETED message must name the date, got %q", w.Message)
		}
	}
}

// TestPreviewReportsOwnedPoliciesAsOrphaned pins the class that is NOT a
// refusal: deliberately leaves a deleted account's policies without
// an owner for re-assignment. That is recoverable, but the admin should be told
// the count BEFORE the delete, not discover it after.
func TestPreviewReportsOwnedPoliciesAsOrphaned(t *testing.T) {
	steps, _, op, _, _ := allPreviewSteps()
	op.items = []userdelete.OwnedPolicy{
		{ID: "p-1", Number: "IT-001", Title: "Access Control"},
		{ID: "p-2", Number: "IT-009", Title: "Old Thing", Retired: true},
		{ID: "p-3"},
	}

	p, err := userdelete.Preview(context.Background(), steps, liveAccount())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if p.Counts.OwnedPolicies != 3 {
		t.Errorf("OwnedPolicies = %d, want 3", p.Counts.OwnedPolicies)
	}
	items := itemsOfKind(p, userdelete.KindOwnedPolicy)
	if len(items) != 3 {
		t.Fatalf("want 3 owned-policy items, got %d", len(items))
	}
	if want := "IT-001 — Access Control"; items[0].Label != want {
		t.Errorf("label = %q, want the merge preview's %q convention", items[0].Label, want)
	}
	if !strings.Contains(items[1].Detail, "retired") {
		t.Errorf("a retired policy must say so: %q", items[1].Detail)
	}
	if !strings.Contains(items[2].Label, "p-3") {
		t.Errorf("a number-less, title-less policy must fall back to its id, got %q", items[2].Label)
	}
	// An owned policy must NOT block: the delete is allowed, it just orphans.
	for _, it := range items {
		if it.BlocksDelete {
			t.Errorf("an owned policy must not block the delete: %+v", it)
		}
	}
	if p.BlocksDelete {
		t.Errorf("owning policies must not set BlocksDelete")
	}
	if !hasWarn(p, userdelete.WarnPoliciesOrphaned) {
		t.Errorf("want %s warning, got %v", userdelete.WarnPoliciesOrphaned, warnCodes(p))
	}
}

// TestPreviewReportsRaciGrantsFromDryRun pins the class exists to
// surface:'s dry run. The rows come back from core, so the preview names
// the grants rather than just counting them.
func TestPreviewReportsRaciGrantsFromDryRun(t *testing.T) {
	steps, _, _, rp, _ := allPreviewSteps()
	rp.items = []userdelete.RaciGrant{
		{CategoryID: "cat-1", Roles: []string{"author", "approve"}},
		{CategoryID: "cat-2"},
	}

	p, err := userdelete.Preview(context.Background(), steps, liveAccount())
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if rp.called != 1 {
		t.Fatalf("the dry run must be called exactly once, got %d", rp.called)
	}
	if got := rp.asked[0]; got != "u-1" {
		t.Errorf("the dry run was asked about %q, want the account being previewed", got)
	}
	if p.Counts.RaciGrants != 2 {
		t.Errorf("RaciGrants = %d, want 2", p.Counts.RaciGrants)
	}
	items := itemsOfKind(p, userdelete.KindRaciGrant)
	if len(items) != 2 {
		t.Fatalf("want 2 RACI items, got %d", len(items))
	}
	if !strings.Contains(items[0].Detail, "author, approve") {
		t.Errorf("the item must name the roles held, got %q", items[0].Detail)
	}
	if !strings.Contains(items[0].Label, "cat-1") {
		t.Errorf("the item must name the category, got %q", items[0].Label)
	}
	if !hasWarn(p, userdelete.WarnRaciGrantsRemoved) {
		t.Errorf("want %s warning, got %v", userdelete.WarnRaciGrantsRemoved, warnCodes(p))
	}
}

// TestPreviewCredentialClasses pins the "changes how they can get in" signal
// the delete preview carries, including its honest
// scope: identity knows about the EMAIL ADDRESS, not about the person.
func TestPreviewCredentialClasses(t *testing.T) {
	t.Run("federated-only account has nothing to lose", func(t *testing.T) {
		steps, _, _, _, cf := allPreviewSteps()
		cf.ref = userdelete.CredentialRef{Found: false}
		acct := liveAccount()
		acct.LocalAccount = false
		acct.Passkeys = 0

		p, err := userdelete.Preview(context.Background(), steps, acct)
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
		if p.LocallyAuthenticable {
			t.Errorf("an SSO-only account with no credential and no passkey is not locally authenticable")
		}
		if !hasWarn(p, userdelete.WarnNoLocalCredential) {
			t.Errorf("want %s, got %v", userdelete.WarnNoLocalCredential, warnCodes(p))
		}
		if hasWarn(p, userdelete.WarnLastLocalCredential) {
			t.Errorf("must not claim a last-local-credential loss when there was none")
		}
	})

	t.Run("only locally-authenticable account on the address", func(t *testing.T) {
		steps, _, _, _, cf := allPreviewSteps()
		cf.ref = userdelete.CredentialRef{ID: "kr-1", Found: true, State: "active"}
		acct := liveAccount()
		acct.OtherLiveAccountsSameEmail = 0
		acct.OtherLocalAccountsSameEmail = 0

		p, err := userdelete.Preview(context.Background(), steps, acct)
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
		if !p.LocallyAuthenticable {
			t.Errorf("an account with a credential is locally authenticable")
		}
		if !hasWarn(p, userdelete.WarnLastLocalCredential) {
			t.Errorf("want %s, got %v", userdelete.WarnLastLocalCredential, warnCodes(p))
		}
		items := itemsOfKind(p, userdelete.KindCredential)
		if len(items) != 1 {
			t.Fatalf("want exactly one credential item, got %d", len(items))
		}
		if !strings.Contains(items[0].Detail, "active") {
			t.Errorf("the credential item must report its state, got %q", items[0].Detail)
		}
		if items[0].RefID != "kr-1" {
			t.Errorf("the credential item must carry the credential id, got %q", items[0].RefID)
		}
	})

	t.Run("a sibling account can still sign in locally", func(t *testing.T) {
		steps, _, _, _, cf := allPreviewSteps()
		cf.ref = userdelete.CredentialRef{ID: "kr-1", Found: true, State: "active"}
		acct := liveAccount()
		acct.OtherLiveAccountsSameEmail = 1
		acct.OtherLocalAccountsSameEmail = 1

		p, err := userdelete.Preview(context.Background(), steps, acct)
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
		if hasWarn(p, userdelete.WarnLastLocalCredential) {
			t.Errorf("another locally-authenticable account on the address exists; must not warn: %v", warnCodes(p))
		}
	})

	t.Run("siblings exist but none can sign in locally", func(t *testing.T) {
		steps, _, _, _, cf := allPreviewSteps()
		cf.ref = userdelete.CredentialRef{ID: "kr-1", Found: true, State: "active"}
		acct := liveAccount()
		acct.OtherLiveAccountsSameEmail = 2
		acct.OtherLocalAccountsSameEmail = 0

		p, err := userdelete.Preview(context.Background(), steps, acct)
		if err != nil {
			t.Fatalf("Preview: %v", err)
		}
		if !hasWarn(p, userdelete.WarnLastLocalCredential) {
			t.Fatalf("want %s, got %v", userdelete.WarnLastLocalCredential, warnCodes(p))
		}
		// The message must be honest that the siblings exist, since that is what
		// the original incident looked like.
		for _, w := range p.Warnings {
			if w.Code == userdelete.WarnLastLocalCredential && !strings.Contains(w.Message, "2 other live account") {
				t.Errorf("the message must name the sibling accounts, got %q", w.Message)
			}
		}
	})

	t.Run("the credential lookup is asked about the account's email", func(t *testing.T) {
		steps, _, _, _, cf := allPreviewSteps()
		if _, err := userdelete.Preview(context.Background(), steps, liveAccount()); err != nil {
			t.Fatalf("Preview: %v", err)
		}
		if len(cf.asked) != 1 || cf.asked[0] != "person@x.example.org" {
			t.Errorf("credential lookup asked %v, want the account's email once", cf.asked)
		}
	})
}

// TestPreviewCountsIdentityOwnedAccessRows pins the classes the delete drops
// inside identity's own database, and the ONE it does not.
func TestPreviewCountsIdentityOwnedAccessRows(t *testing.T) {
	steps, _, _, _, _ := allPreviewSteps()
	acct := liveAccount()
	acct.Roles = []string{"site-admin"}
	acct.ScopedRoles = []string{"author (IT Security)", "approver (HR)"}
	acct.Permissions = []string{"policy.read_sensitive"}
	acct.GroupLabels = []string{"Finance", "IT"}
	acct.IdpGroups = []string{"CN=Staff"}
	acct.PolicyOverrides = []string{"IT-001 (deny)"}
	acct.BreakGlassGrants = 3
	acct.ManagedGroups = 2

	p, err := userdelete.Preview(context.Background(), steps, acct)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if p.Counts.Roles != 3 {
		t.Errorf("Roles = %d, want 3 (global + category-scoped)", p.Counts.Roles)
	}
	if p.Counts.Permissions != 1 {
		t.Errorf("Permissions = %d, want 1", p.Counts.Permissions)
	}
	if p.Counts.GroupMemberships != 2 {
		t.Errorf("GroupMemberships = %d, want 2", p.Counts.GroupMemberships)
	}
	if p.Counts.IdpGroups != 1 {
		t.Errorf("IdpGroups = %d, want 1", p.Counts.IdpGroups)
	}
	if p.Counts.PolicyOverrides != 1 {
		t.Errorf("PolicyOverrides = %d, want 1", p.Counts.PolicyOverrides)
	}
	if p.Counts.BreakGlassGrants != 3 {
		t.Errorf("BreakGlassGrants = %d, want 3", p.Counts.BreakGlassGrants)
	}
	if p.Counts.ManagedGroups != 2 {
		t.Errorf("ManagedGroups = %d, want 2", p.Counts.ManagedGroups)
	}
	// Group memberships must be NAMED, not shown as UUIDs.
	var sawFinance bool
	for _, it := range itemsOfKind(p, userdelete.KindAccessRow) {
		if it.Label == "Finance" {
			sawFinance = true
		}
	}
	if !sawFinance {
		t.Errorf("group memberships must be rendered by name")
	}
	// group_managers is the one class DeleteUser does NOT clear.
	if !hasWarn(p, userdelete.WarnRetainedManagedGroups) {
		t.Fatalf("want %s — DeleteUser does not touch group_managers, so the grants survive pointing at a tombstone; got %v",
			userdelete.WarnRetainedManagedGroups, warnCodes(p))
	}
	var sawRetained bool
	for _, it := range itemsOfKind(p, userdelete.KindAccessRow) {
		if strings.Contains(it.Detail, "NOT removed") {
			sawRetained = true
		}
	}
	if !sawRetained {
		t.Errorf("the group-manager item must say it is NOT removed, or an admin will assume it is")
	}
}

// TestPreviewCleanAccountIsAllowedAndSilent: the ordinary case. Nothing blocks,
// and the only warning is the honest "no local credential" note.
func TestPreviewCleanAccountIsAllowed(t *testing.T) {
	steps, _, _, _, cf := allPreviewSteps()
	cf.ref = userdelete.CredentialRef{Found: true, State: "active"}
	acct := liveAccount()
	acct.OtherLocalAccountsSameEmail = 1

	p, err := userdelete.Preview(context.Background(), steps, acct)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if p.BlocksDelete {
		t.Errorf("a clean account must not block: warnings %v", warnCodes(p))
	}
	if len(p.Warnings) != 0 {
		t.Errorf("a clean account with a locally-authenticable sibling needs no warnings, got %v", warnCodes(p))
	}
	if p.UserID != "u-1" {
		t.Errorf("UserID = %q, want the previewed account", p.UserID)
	}
}
