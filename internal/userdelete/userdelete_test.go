// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
)

type stubLister struct {
	items  []userdelete.PendingApproval
	err    error
	called int
}

func (s *stubLister) ListPendingApprovals(_ context.Context, _ string) ([]userdelete.PendingApproval, error) {
	s.called++
	return s.items, s.err
}

type stubRevoker struct {
	res    kratos.RevokeResult
	err    error
	called int
}

func (s *stubRevoker) RevokeIdentity(_ context.Context, _ string) (kratos.RevokeResult, error) {
	s.called++
	return s.res, s.err
}

// TestCheckPassesWhenNoPendingApprovals proves the ordinary case: the approval
// check finds nothing, the credential revoke runs, and its outcome is returned
// for the audit trail.
func TestCheckPassesWhenNoPendingApprovals(t *testing.T) {
	l := &stubLister{}
	r := &stubRevoker{res: kratos.RevokeResult{IdentityID: "k1", Found: true, Deactivated: true}}

	res, err := userdelete.Check(context.Background(), allSteps(l, r, &stubPurger{}), userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if l.called != 1 || r.called != 1 {
		t.Fatalf("calls: lister=%d revoker=%d, want 1/1", l.called, r.called)
	}
	if !res.Revoke.Deactivated || res.Revoke.IdentityID != "k1" {
		t.Fatalf("Result.Revoke: got %+v", res.Revoke)
	}
}

// TestCheckRefusesOnPendingApprovalsBeforeRevoking is the ordering guarantee:
// an admin told to reassign approvals first must not discover that the account
// has meanwhile had its credential revoked, so a refusal must happen before any
// credential mutation.
func TestCheckRefusesOnPendingApprovalsBeforeRevoking(t *testing.T) {
	l := &stubLister{items: []userdelete.PendingApproval{{PolicyTitle: "Backup and Recovery"}}}
	r := &stubRevoker{}

	_, err := userdelete.Check(context.Background(), allSteps(l, r, &stubPurger{}), userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})
	var pending *userdelete.PendingApprovalsError
	if !errors.As(err, &pending) {
		t.Fatalf("Check: got %v, want *PendingApprovalsError", err)
	}
	if len(pending.Items) != 1 {
		t.Fatalf("Items: got %d, want 1", len(pending.Items))
	}
	if r.called != 0 {
		t.Fatalf("revoker called %d times on a refusal, want 0", r.called)
	}
}

// TestCheckFailsClosedOnApprovalListError proves a workflow that cannot answer
// is never read as "this user holds no approvals".
func TestCheckFailsClosedOnApprovalListError(t *testing.T) {
	r := &stubRevoker{}
	_, err := userdelete.Check(context.Background(),
		allSteps(&stubLister{err: errors.New("boom")}, r, &stubPurger{}), userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})

	var unavailable *userdelete.StepUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Check: got %v, want *StepUnavailableError", err)
	}
	if unavailable.Step != userdelete.StepApprovalCheck {
		t.Fatalf("Step: got %q, want %q", unavailable.Step, userdelete.StepApprovalCheck)
	}
	if r.called != 0 {
		t.Fatalf("revoker called %d times, want 0", r.called)
	}
}

// TestCheckFailsClosedOnRevokeError proves a credential store that cannot
// answer blocks the delete rather than being skipped.
func TestCheckFailsClosedOnRevokeError(t *testing.T) {
	_, err := userdelete.Check(context.Background(),
		allSteps(&stubLister{}, &stubRevoker{err: errors.New("kratos down")}, &stubPurger{}), userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})

	var unavailable *userdelete.StepUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Check: got %v, want *StepUnavailableError", err)
	}
	if unavailable.Step != userdelete.StepCredentialRevoke {
		t.Fatalf("Step: got %q, want %q", unavailable.Step, userdelete.StepCredentialRevoke)
	}
}

// TestCheckFailsClosedOnNilSeams proves an unwired client is a refusal, not a
// silent skip — the pre- behaviour it replaces.
func TestCheckFailsClosedOnNilSeams(t *testing.T) {
	var unavailable *userdelete.StepUnavailableError

	_, err := userdelete.Check(context.Background(),
		userdelete.Steps{Credentials: &stubRevoker{}, CategoryRules: &stubPurger{}}, userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})
	if !errors.As(err, &unavailable) || unavailable.Step != userdelete.StepApprovalCheck {
		t.Fatalf("nil lister: got %v, want StepUnavailableError(approval_check)", err)
	}

	_, err = userdelete.Check(context.Background(),
		userdelete.Steps{Approvals: &stubLister{}, CategoryRules: &stubPurger{}}, userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})
	if !errors.As(err, &unavailable) || unavailable.Step != userdelete.StepCredentialRevoke {
		t.Fatalf("nil revoker: got %v, want StepUnavailableError(credential_revoke)", err)
	}
}

// TestDescribeApprovalsNamesPoliciesStagesAndDates covers the refusal message
// body: the admin has to be able to act without hunting, so each row names the
// policy, its 1-based stage and its SLA date.
func TestDescribeApprovalsNamesPoliciesStagesAndDates(t *testing.T) {
	due := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	got := userdelete.DescribeApprovals([]userdelete.PendingApproval{
		{PolicyTitle: "Artificial Intelligence (AI)", StageIndex: 0, DueAt: due},
		{PolicyTitle: "Backup and Recovery", StageIndex: 1, DueAt: due},
	}, 0)

	for _, want := range []string{
		`"Artificial Intelligence (AI)" (stage 1, due 2026-08-13)`,
		`"Backup and Recovery" (stage 2, due 2026-08-13)`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("DescribeApprovals missing %s; got %s", want, got)
		}
	}
}

// TestDescribeApprovalsFallsBackToVersionID proves a title-less row is still
// identifiable rather than rendered as an empty pair of quotes.
func TestDescribeApprovalsFallsBackToVersionID(t *testing.T) {
	got := userdelete.DescribeApprovals([]userdelete.PendingApproval{
		{PolicyVersionID: "00c14e95-1111-2222-3333-444444444444"},
	}, 0)
	if !strings.Contains(got, "00c14e95-1111-2222-3333-444444444444") {
		t.Fatalf("DescribeApprovals: got %s", got)
	}
}

// TestDescribeApprovalsTruncatesLongLists keeps a user-facing message readable
// while still reporting the true total.
func TestDescribeApprovalsTruncatesLongLists(t *testing.T) {
	items := make([]userdelete.PendingApproval, 8)
	for i := range items {
		items[i] = userdelete.PendingApproval{PolicyTitle: "P"}
	}
	got := userdelete.DescribeApprovals(items, 0)
	if !strings.HasSuffix(got, "and 3 more") {
		t.Fatalf("DescribeApprovals: got %q, want a trailing \"and 3 more\"", got)
	}
}

// ---: the third pre-delete step (category-rule purge) ---------------

type stubPurger struct {
	res    userdelete.PurgeResult
	err    error
	asked  []string
	actors []string
	called int
}

func (s *stubPurger) PurgeUserCategoryRules(_ context.Context, userID, actorUserID string) (userdelete.PurgeResult, error) {
	s.called++
	s.asked = append(s.asked, userID)
	s.actors = append(s.actors, actorUserID)
	return s.res, s.err
}

// allSteps wires every seam with a passing stub, so a test only has to say
// which one it is bending.
func allSteps(l *stubLister, r *stubRevoker, p *stubPurger) userdelete.Steps {
	return userdelete.Steps{Approvals: l, Credentials: r, CategoryRules: p}
}

// TestCheckPurgesUserCategoryRules proves the third step runs on the ordinary
// path and reports what it removed. Before the deleted account's
// user-subject RACI rules survived in core as dead config naming a nonexistent
// user (found in prod 2026-09-15).
func TestCheckPurgesUserCategoryRules(t *testing.T) {
	l := &stubLister{}
	r := &stubRevoker{res: kratos.RevokeResult{IdentityID: "k1", Found: true}}
	p := &stubPurger{res: userdelete.PurgeResult{
		RemovedRules:        2,
		AffectedCategoryIDs: []string{"956dc2ab-d9af-44b3-9a38-33e6a87dd49c"},
	}}

	res, err := userdelete.Check(context.Background(), allSteps(l, r, p), userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if p.called != 1 || len(p.asked) != 1 || p.asked[0] != "u1" {
		t.Fatalf("purger calls: called=%d asked=%v, want 1 call for u1", p.called, p.asked)
	}
	// The deleting admin must ride along: core records actor_user_id on the
	// per-grant revoke events, and an unattributed permissions change is the
	// audit defect this estate already had once.
	if len(p.actors) != 1 || p.actors[0] != "admin-1" {
		t.Fatalf("purger actor: got %v, want [admin-1]", p.actors)
	}
	if res.Purge.RemovedRules != 2 || len(res.Purge.AffectedCategoryIDs) != 1 {
		t.Fatalf("Result.Purge: got %+v, want 2 rules in 1 category", res.Purge)
	}
}

// TestCheckStepOrder pins the ORDER of the three steps, which is a deliberate
// blast-radius decision and not an implementation detail:
//
//   - a refusal (pending approvals) must precede every write, so an admin told
//     to reassign approvals first does not find the account already changed;
//   - the credential revoke precedes the purge, so a core outage leaves a
//     locked-out-but-intact account rather than an account that still works but
//     has silently lost its category grants.
func TestCheckStepOrder(t *testing.T) {
	for _, tc := range []struct {
		name        string
		lister      *stubLister
		revoker     *stubRevoker
		purger      *stubPurger
		wantRevoked int
		wantPurged  int
		wantStep    string
		wantRefusal bool
	}{
		{
			name:        "pending approvals refuse before any write",
			lister:      &stubLister{items: []userdelete.PendingApproval{{PolicyTitle: "Backup and Recovery"}}},
			revoker:     &stubRevoker{},
			purger:      &stubPurger{},
			wantRefusal: true,
		},
		{
			name:     "approval check unavailable stops before any write",
			lister:   &stubLister{err: errors.New("workflow unreachable")},
			revoker:  &stubRevoker{},
			purger:   &stubPurger{},
			wantStep: userdelete.StepApprovalCheck,
		},
		{
			name:        "revoke failure stops before the purge",
			lister:      &stubLister{},
			revoker:     &stubRevoker{err: errors.New("kratos down")},
			purger:      &stubPurger{},
			wantRevoked: 1,
			wantPurged:  0,
			wantStep:    userdelete.StepCredentialRevoke,
		},
		{
			name:        "purge failure comes last, with the revoke already done",
			lister:      &stubLister{},
			revoker:     &stubRevoker{},
			purger:      &stubPurger{err: errors.New("core unreachable")},
			wantRevoked: 1,
			wantPurged:  1,
			wantStep:    userdelete.StepCategoryRulePurge,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := userdelete.Check(context.Background(),
				allSteps(tc.lister, tc.revoker, tc.purger), userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})
			if err == nil {
				t.Fatal("Check: got nil error, want a refusal")
			}
			if tc.wantRefusal {
				if _, ok := errors.AsType[*userdelete.PendingApprovalsError](err); !ok {
					t.Fatalf("Check: got %v, want *PendingApprovalsError", err)
				}
			} else {
				var unavailable *userdelete.StepUnavailableError
				if !errors.As(err, &unavailable) {
					t.Fatalf("Check: got %v, want *StepUnavailableError", err)
				}
				if unavailable.Step != tc.wantStep {
					t.Fatalf("Step: got %q, want %q", unavailable.Step, tc.wantStep)
				}
			}
			if tc.revoker.called != tc.wantRevoked {
				t.Errorf("revoker calls: got %d, want %d", tc.revoker.called, tc.wantRevoked)
			}
			if tc.purger.called != tc.wantPurged {
				t.Errorf("purger calls: got %d, want %d", tc.purger.called, tc.wantPurged)
			}
		})
	}
}

// TestCheckFailsClosedOnNilPurger proves an unwired core client is a REFUSAL,
// not a skip. Skipping is precisely the pre- behaviour that left the
// prod orphan, and unlike a stranded approval seat nothing surfaces a dead
// grant later — so it must never be optional.
func TestCheckFailsClosedOnNilPurger(t *testing.T) {
	r := &stubRevoker{}
	_, err := userdelete.Check(context.Background(),
		userdelete.Steps{Approvals: &stubLister{}, Credentials: r}, userdelete.Target{UserID: "u1", Email: "u1@example.com", ActorUserID: "admin-1"})

	var unavailable *userdelete.StepUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Check: got %v, want *StepUnavailableError", err)
	}
	if unavailable.Step != userdelete.StepCategoryRulePurge {
		t.Fatalf("Step: got %q, want %q", unavailable.Step, userdelete.StepCategoryRulePurge)
	}
}
