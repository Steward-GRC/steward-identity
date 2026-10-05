// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/merge"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeCore implements merge.CoreClient. It records call counts so the resume
// test can prove an already-completed step is NOT re-invoked.
type fakeCore struct {
	policies       []merge.PolicyRef
	versions       map[string]merge.PolicyVersionRef
	versionErr     error
	versionCalls   int
	ownerCount     int
	authorGrants   int
	reassignCalls  int
	listCalls      int
	reassignErr    error
	lastReassignTo string
}

func (f *fakeCore) ListPoliciesByOwner(_ context.Context, _ string, _ bool) ([]merge.PolicyRef, error) {
	f.listCalls++
	return f.policies, nil
}

func (f *fakeCore) GetPolicyVersion(_ context.Context, versionID string) (merge.PolicyVersionRef, error) {
	f.versionCalls++
	if f.versionErr != nil {
		return merge.PolicyVersionRef{}, f.versionErr
	}
	return f.versions[versionID], nil
}

func (f *fakeCore) ReassignUserPolicies(_ context.Context, _, toUserID, _ string) ([]string, int, int, error) {
	f.reassignCalls++
	f.lastReassignTo = toUserID
	if f.reassignErr != nil {
		return nil, 0, 0, f.reassignErr
	}
	ids := make([]string, 0, len(f.policies))
	for _, p := range f.policies {
		ids = append(ids, p.ID)
	}
	return ids, f.ownerCount, f.authorGrants, nil
}

// fakeAck implements merge.AckClient. failUntil>0 makes the first failUntil
// non-dry-run calls fail (to drive the partial/resume path).
type fakeAck struct {
	moved         int
	deduped       int
	items         []merge.AckItem
	transferCalls int
	dryRunCalls   int
	failUntil     int
	lastDryRun    bool
}

func (f *fakeAck) TransferAcknowledgments(_ context.Context, _, _, _ string, dryRun bool, _ string) (int, int, []merge.AckItem, error) {
	f.lastDryRun = dryRun
	if dryRun {
		f.dryRunCalls++
		return f.moved, f.deduped, f.items, nil
	}
	f.transferCalls++
	if f.transferCalls <= f.failUntil {
		return 0, 0, nil, errors.New("the obligations service unavailable")
	}
	return f.moved, f.deduped, f.items, nil
}

// fakeWorkflow implements merge.WorkflowClient. It records call counts so the
// happy-path test can prove the reassign runs non-dry-run and the resume test can
// prove it runs exactly once across a resumed merge.
type fakeWorkflow struct {
	reassigned    int
	deduped       int
	runs          int
	reassignCalls int
	dryRunCalls   int
	lastDryRun    bool
}

func (f *fakeWorkflow) ReassignUserWorkflowItems(_ context.Context, _, _, _ string, dryRun bool, _ string) (int, int, int, error) {
	f.lastDryRun = dryRun
	if dryRun {
		f.dryRunCalls++
		return f.reassigned, f.deduped, f.runs, nil
	}
	f.reassignCalls++
	return f.reassigned, f.deduped, f.runs, nil
}

func mergeHandler(t *testing.T, s *store.Store, core merge.CoreClient, ack merge.AckClient, wf merge.WorkflowClient, pub *capturePublisher) *handlers.AdminHandler {
	t.Helper()
	if wf == nil {
		wf = &fakeWorkflow{}
	}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth).WithSignIn(kratosFor(s))
	h = h.WithMerge(merge.New(s, core, ack, wf, h))
	if pub != nil {
		h = h.WithMembershipPublisher(pub)
	}
	return h
}

func hasAuditEvent(t *testing.T, s *store.Store, eventType string) *store.AuditEvent {
	t.Helper()
	events, err := s.PendingAuditEvents(context.Background(), 500)
	if err != nil {
		t.Fatalf("PendingAuditEvents: %v", err)
	}
	for i := range events {
		if events[i].EventType == eventType {
			return &events[i]
		}
	}
	return nil
}

// TestPreviewAccountMerge proves the dry-run reports exactly what would move and
// mutates nothing.
func TestPreviewAccountMerge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-mrg-admin", "madmin@e", "Admin")
	source, _ := s.JITProvision(ctx, "kc-mrg-src", "src@e", "Source")
	target, _ := s.JITProvision(ctx, "kc-mrg-tgt", "tgt@e", "Target")
	// Give the source a timezone the (empty) target should inherit.
	if _, err := s.UpdateUserProfile(ctx, source.ID, "src@e", "Source", "", "", "America/New_York", ""); err != nil {
		t.Fatalf("UpdateUserProfile: %v", err)
	}

	core := &fakeCore{
		policies:     []merge.PolicyRef{{ID: "p1", Number: "POL-1", Title: "One"}, {ID: "p2", Number: "POL-2", Title: "Two"}},
		ownerCount:   2,
		authorGrants: 3,
		versions: map[string]merge.PolicyVersionRef{
			"pv1": {ID: "pv1", PolicyID: "p1", PolicyNumber: "POL-1", PolicyTitle: "One", VersionNo: 3},
		},
	}
	ack := &fakeAck{moved: 1, deduped: 1, items: []merge.AckItem{
		{PolicyVersionID: "pv1", Resolution: "moved", SourceAckedAt: time.Now()},
		{PolicyVersionID: "pv2", Resolution: "kept_earliest", SourceAckedAt: time.Now(), TargetAckedAt: time.Now()},
	}}
	wf := &fakeWorkflow{reassigned: 2, runs: 1}
	h := mergeHandler(t, s, core, ack, wf, nil)

	resp, err := h.PreviewAccountMerge(adminCtx(admin.ID.String()),
		&identityv1.PreviewAccountMergeRequest{SourceUserId: source.ID.String(), TargetUserId: target.ID.String()})
	if err != nil {
		t.Fatalf("PreviewAccountMerge: %v", err)
	}
	p := resp.GetPreview()
	if p.GetCounts().GetPoliciesOwned() != 2 {
		t.Fatalf("policies_owned: got %d want 2", p.GetCounts().GetPoliciesOwned())
	}
	if p.GetCounts().GetAcknowledgmentsMoved() != 1 || p.GetCounts().GetAcknowledgmentsDeduped() != 1 {
		t.Fatalf("ack counts: moved=%d deduped=%d want 1/1", p.GetCounts().GetAcknowledgmentsMoved(), p.GetCounts().GetAcknowledgmentsDeduped())
	}
	if p.GetCounts().GetPreferences() != 1 {
		t.Fatalf("preferences: got %d want 1 (timezone)", p.GetCounts().GetPreferences())
	}
	if p.GetRequiresPrivilegedConfirm() {
		t.Fatal("plain user source must not require privileged confirm")
	}
	if !ack.lastDryRun {
		t.Fatal("preview must call the ack transfer in dry-run mode")
	}
	if p.GetCounts().GetWorkflowItems() != 3 {
		t.Fatalf("workflow_items: got %d want 3 (2 seats + 1 run)", p.GetCounts().GetWorkflowItems())
	}
	if wf.reassignCalls != 0 || wf.dryRunCalls != 1 || !wf.lastDryRun {
		t.Fatalf("preview must call workflow reassign in dry-run only: reassignCalls=%d dryRunCalls=%d lastDryRun=%v", wf.reassignCalls, wf.dryRunCalls, wf.lastDryRun)
	}
	// Acknowledgment rows name the policy. pv1 resolves; pv2 does
	// not, and must still appear with the raw-id fallback rather than dropping
	// out of the review list.
	ackLabels := map[string]string{}
	for _, it := range p.GetItems() {
		if it.GetKind() == identityv1.MergeItemKind_MERGE_ITEM_KIND_ACKNOWLEDGMENT {
			ackLabels[it.GetRefId()] = it.GetLabel()
		}
	}
	if len(ackLabels) != 2 {
		t.Fatalf("got %d acknowledgment rows, want 2", len(ackLabels))
	}
	if want := "POL-1 — One (v3)"; ackLabels["pv1"] != want {
		t.Errorf("pv1 label = %q, want %q", ackLabels["pv1"], want)
	}
	if want := "Policy version pv2"; ackLabels["pv2"] != want {
		t.Errorf("pv2 label = %q, want the raw-id fallback %q", ackLabels["pv2"], want)
	}

	// Nothing mutated: source still enabled, target timezone untouched.
	if su, _ := s.GetUser(ctx, source.ID); !su.Enabled {
		t.Fatal("preview must not disable the source")
	}
	if tu, _ := s.GetUser(ctx, target.ID); tu.Timezone != "" {
		t.Fatal("preview must not move preferences")
	}
}

// TestPreviewSiteAdminSourceWarns proves a site-admin source flags the
// privileged-confirm requirement.
func TestPreviewSiteAdminSourceWarns(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-mrg-a2", "a2@e", "Admin2")
	source, _ := s.JITProvision(ctx, "kc-mrg-sa", "sa@e", "SA")
	target, _ := s.JITProvision(ctx, "kc-mrg-t2", "t2@e", "T2")
	if _, err := s.GrantRole(ctx, source.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	h := mergeHandler(t, s, &fakeCore{}, &fakeAck{}, &fakeWorkflow{}, nil)

	resp, err := h.PreviewAccountMerge(adminCtx(admin.ID.String()),
		&identityv1.PreviewAccountMergeRequest{SourceUserId: source.ID.String(), TargetUserId: target.ID.String()})
	if err != nil {
		t.Fatalf("PreviewAccountMerge: %v", err)
	}
	if !resp.GetPreview().GetRequiresPrivilegedConfirm() {
		t.Fatal("site-admin source must require privileged confirm")
	}
}

// TestMergeAccountsHappyPath proves the full orchestration: counts flow through,
// downstream steps run (non-dry-run), the source is tombstoned with its session
// revoked, the single dual-attributed audit event is emitted, the source's prior
// audit stays intact, and membership.changed fires.
func TestMergeAccountsHappyPath(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-mrg-a3", "a3@e", "Admin3")
	source, _ := s.JITProvision(ctx, "kc-mrg-s3", "s3@e", "Source3")
	target, _ := s.JITProvision(ctx, "kc-mrg-tg3", "tg3@e", "Target3")
	kratosFor(s).addSession("kc-mrg-s3", true)
	core := &fakeCore{policies: []merge.PolicyRef{{ID: "p1", Number: "POL-1"}}, ownerCount: 1, authorGrants: 2}
	ack := &fakeAck{moved: 4, deduped: 1}
	wf := &fakeWorkflow{reassigned: 3, deduped: 1, runs: 2}
	pub := &capturePublisher{}
	h := mergeHandler(t, s, core, ack, wf, pub)

	resp, err := h.MergeAccounts(adminCtx(admin.ID.String()), &identityv1.MergeAccountsRequest{
		SourceUserId: source.ID.String(), TargetUserId: target.ID.String(),
	})
	if err != nil {
		t.Fatalf("MergeAccounts: %v", err)
	}
	if resp.GetStatus() != identityv1.MergeStatus_MERGE_STATUS_COMPLETED {
		t.Fatalf("status: got %v want COMPLETED (steps: %+v)", resp.GetStatus(), resp.GetSteps())
	}
	if resp.GetCounts().GetPoliciesOwned() != 1 || resp.GetCounts().GetRaciGrants() != 2 {
		t.Fatalf("policy counts: %+v", resp.GetCounts())
	}
	if resp.GetCounts().GetAcknowledgmentsMoved() != 4 || resp.GetCounts().GetAcknowledgmentsDeduped() != 1 {
		t.Fatalf("ack counts: %+v", resp.GetCounts())
	}
	if core.reassignCalls != 1 {
		t.Fatalf("core reassign calls: got %d want 1", core.reassignCalls)
	}
	if ack.transferCalls != 1 || ack.lastDryRun {
		t.Fatalf("ack transfer must run once non-dry-run: calls=%d dryRun=%v", ack.transferCalls, ack.lastDryRun)
	}
	// The workflow step ran non-dry-run and its counts flowed through.
	if wf.reassignCalls != 1 || wf.lastDryRun {
		t.Fatalf("workflow reassign must run once non-dry-run: calls=%d dryRun=%v", wf.reassignCalls, wf.lastDryRun)
	}
	if resp.GetCounts().GetWorkflowItems() != 5 {
		t.Fatalf("workflow_items count: got %d want 5 (3 seats + 2 runs)", resp.GetCounts().GetWorkflowItems())
	}
	var wfCompleted bool
	for _, st := range resp.GetSteps() {
		if st.GetStep() == "workflow_reassign" && st.GetStatus() == identityv1.MergeStepStatus_MERGE_STEP_STATUS_COMPLETED {
			wfCompleted = true
		}
	}
	if !wfCompleted {
		t.Fatal("workflow_reassign must be reported COMPLETED")
	}
	// Source tombstoned (disabled).
	su, err := s.GetUser(ctx, source.ID)
	if err != nil {
		t.Fatalf("GetUser(source): %v", err)
	}
	if su.Enabled {
		t.Fatal("merged source must be disabled (tombstoned)")
	}
	// Exactly one dual-attributed merge event, target = subject, source in payload.
	ev := hasAuditEvent(t, s, "user.accounts_merged")
	if ev == nil {
		t.Fatal("expected a user.accounts_merged audit event")
	}
	if ev.TargetUserID == nil || *ev.TargetUserID != target.ID {
		t.Fatalf("merge event target: got %v want %v", ev.TargetUserID, target.ID)
	}
	if ev.Payload["from_user_id"] != source.ID.String() || ev.Payload["into_user_id"] != target.ID.String() {
		t.Fatalf("merge event payload wrong: %+v", ev.Payload)
	}
	// Audit immutability: the source's original user.created event still exists.
	if hasAuditEvent(t, s, "user.created") == nil {
		t.Fatal("prior audit (user.created) must remain intact after merge")
	}
	// A session was revoked and membership.changed emitted.
	if hasAuditEvent(t, s, "session.revoked") == nil {
		t.Fatal("expected the source session to be revoked")
	}
	if !pub.has("membership.changed") {
		t.Fatalf("expected membership.changed, got %v", pub.snapshot())
	}
}

// TestMergeSelfRejected proves source==target is refused with no mutation.
func TestMergeSelfRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-mrg-a4", "a4@e", "Admin4")
	u, _ := s.JITProvision(ctx, "kc-mrg-self", "self@e", "Self")
	h := mergeHandler(t, s, &fakeCore{}, &fakeAck{}, &fakeWorkflow{}, nil)
	_, err := h.MergeAccounts(adminCtx(admin.ID.String()),
		&identityv1.MergeAccountsRequest{SourceUserId: u.ID.String(), TargetUserId: u.ID.String()})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("self-merge: got %v want InvalidArgument", err)
	}
}

// TestMergeRootRejected proves the root account cannot be a merge source.
func TestMergeRootRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-mrg-a5", "a5@e", "Admin5")
	root, err := s.PreCreateLocalUserRoot(ctx, "root-mrg", "root-mrg@e", "Root")
	if err != nil {
		t.Fatalf("PreCreateLocalUserRoot: %v", err)
	}
	target, _ := s.JITProvision(ctx, "kc-mrg-tg5", "tg5@e", "Target5")
	h := mergeHandler(t, s, &fakeCore{}, &fakeAck{}, &fakeWorkflow{}, nil)
	_, err = h.MergeAccounts(adminCtx(admin.ID.String()),
		&identityv1.MergeAccountsRequest{SourceUserId: root.ID.String(), TargetUserId: target.ID.String()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("root source: got %v want FailedPrecondition", err)
	}
}

// TestMergeSiteAdminRequiresConfirm proves a site-admin source needs
// confirm_privileged, and proceeds once it is set.
func TestMergeSiteAdminRequiresConfirm(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-mrg-a6", "a6@e", "Admin6")
	source, _ := s.JITProvision(ctx, "kc-mrg-sa6", "sa6@e", "SA6")
	target, _ := s.JITProvision(ctx, "kc-mrg-tg6", "tg6@e", "Target6")
	if _, err := s.GrantRole(ctx, source.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	h := mergeHandler(t, s, &fakeCore{ownerCount: 0}, &fakeAck{}, &fakeWorkflow{}, &capturePublisher{})

	_, err := h.MergeAccounts(adminCtx(admin.ID.String()),
		&identityv1.MergeAccountsRequest{SourceUserId: source.ID.String(), TargetUserId: target.ID.String()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("site-admin without confirm: got %v want FailedPrecondition", err)
	}
	resp, err := h.MergeAccounts(adminCtx(admin.ID.String()),
		&identityv1.MergeAccountsRequest{SourceUserId: source.ID.String(), TargetUserId: target.ID.String(), ConfirmPrivileged: true})
	if err != nil {
		t.Fatalf("site-admin with confirm: %v", err)
	}
	if resp.GetStatus() != identityv1.MergeStatus_MERGE_STATUS_COMPLETED {
		t.Fatalf("confirmed merge status: got %v want COMPLETED", resp.GetStatus())
	}
}

// TestMergeIdempotentResumablePartial is the data-safety proof: a mid-merge
// failure leaves the source intact (NOT tombstoned) and re-running with the same
// key resumes — the already-completed core step is NOT re-invoked and the merge
// then completes.
func TestMergeIdempotentResumablePartial(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-mrg-a7", "a7@e", "Admin7")
	source, _ := s.JITProvision(ctx, "kc-mrg-s7", "s7@e", "Source7")
	target, _ := s.JITProvision(ctx, "kc-mrg-tg7", "tg7@e", "Target7")

	core := &fakeCore{policies: []merge.PolicyRef{{ID: "p1", Number: "POL-1"}}, ownerCount: 1, authorGrants: 1}
	ack := &fakeAck{moved: 2, deduped: 0, failUntil: 1} // first non-dry-run ack call fails
	wf := &fakeWorkflow{reassigned: 1, runs: 0}
	h := mergeHandler(t, s, core, ack, wf, &capturePublisher{})

	key := "merge-resume-test"
	resp, err := h.MergeAccounts(adminCtx(admin.ID.String()), &identityv1.MergeAccountsRequest{
		SourceUserId: source.ID.String(), TargetUserId: target.ID.String(), IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("MergeAccounts (first): %v", err)
	}
	if resp.GetStatus() != identityv1.MergeStatus_MERGE_STATUS_PARTIAL {
		t.Fatalf("first run status: got %v want PARTIAL (steps %+v)", resp.GetStatus(), resp.GetSteps())
	}
	// Source must NOT be tombstoned after a partial failure.
	if su, _ := s.GetUser(ctx, source.ID); !su.Enabled {
		t.Fatal("source must remain enabled after a PARTIAL merge (no data loss / no premature tombstone)")
	}
	if hasAuditEvent(t, s, "user.accounts_merged") != nil {
		t.Fatal("no merge event must be emitted on a partial merge")
	}
	// The workflow step (step 3) sits after the ack step that failed, so it must
	// not have run yet on the partial attempt.
	if wf.reassignCalls != 0 {
		t.Fatalf("workflow reassign must not run when an earlier step failed, got %d calls", wf.reassignCalls)
	}

	// Re-run with the SAME key: resumes, skipping the completed core step.
	resp2, err := h.MergeAccounts(adminCtx(admin.ID.String()), &identityv1.MergeAccountsRequest{
		SourceUserId: source.ID.String(), TargetUserId: target.ID.String(), IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("MergeAccounts (resume): %v", err)
	}
	if resp2.GetStatus() != identityv1.MergeStatus_MERGE_STATUS_COMPLETED {
		t.Fatalf("resume status: got %v want COMPLETED (steps %+v)", resp2.GetStatus(), resp2.GetSteps())
	}
	if core.reassignCalls != 1 {
		t.Fatalf("core reassign must run exactly once across a resumed merge, got %d", core.reassignCalls)
	}
	if wf.reassignCalls != 1 {
		t.Fatalf("workflow reassign must run exactly once across a resumed merge, got %d", wf.reassignCalls)
	}
	if su, _ := s.GetUser(ctx, source.ID); su.Enabled {
		t.Fatal("source must be tombstoned after the resumed merge completes")
	}
	if hasAuditEvent(t, s, "user.accounts_merged") == nil {
		t.Fatal("merge event must be emitted once the resumed merge completes")
	}
}

// TestMergeUnconfigured proves the RPCs fail closed when the orchestrator is not
// wired.
func TestMergeUnconfigured(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-mrg-a8", "a8@e", "Admin8")
	h := handlers.NewAdminHandler(s, testAdminAuth())
	_, err := h.MergeAccounts(adminCtx(admin.ID.String()),
		&identityv1.MergeAccountsRequest{SourceUserId: admin.ID.String(), TargetUserId: admin.ID.String()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("unconfigured merge: got %v want Unavailable", err)
	}
}

// TestMergeUnknownUser proves a missing source yields NotFound.
func TestMergeUnknownUser(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-mrg-a9", "a9@e", "Admin9")
	target, _ := s.JITProvision(context.Background(), "kc-mrg-tg9", "tg9@e", "Target9")
	h := mergeHandler(t, s, &fakeCore{}, &fakeAck{}, &fakeWorkflow{}, nil)
	_, err := h.MergeAccounts(adminCtx(admin.ID.String()), &identityv1.MergeAccountsRequest{
		SourceUserId: "00000000-0000-0000-0000-000000000000", TargetUserId: target.ID.String(),
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown source: got %v want NotFound", err)
	}
}
