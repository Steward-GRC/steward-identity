// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	corev1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
)

// These tests exercise the real generated core clients over an in-process gRPC
// connection, because the property they pin lives in the REQUEST the adapter
// sends — dry_run=true — and a hand-written fake of the Go interface would just
// be asserting my own struct literal back at me.

// fakeGroupService records the PurgeUserCategoryRules request it received.
// Embedding UnimplementedCategoryServiceServer keeps the other 11 RPCs out of the
// test.
type fakeGroupService struct {
	corev1.UnimplementedCategoryServiceServer
	got  *corev1.PurgeUserCategoryRulesRequest
	resp *corev1.PurgeUserCategoryRulesResponse
}

func (f *fakeGroupService) PurgeUserCategoryRules(_ context.Context, req *corev1.PurgeUserCategoryRulesRequest) (*corev1.PurgeUserCategoryRulesResponse, error) {
	f.got = req
	if f.resp != nil {
		return f.resp, nil
	}
	return &corev1.PurgeUserCategoryRulesResponse{}, nil
}

// fakePolicyService answers ListPoliciesByOwner and records the request.
type fakePolicyService struct {
	corev1.UnimplementedPolicyServiceServer
	got  *corev1.ListPoliciesByOwnerRequest
	resp *corev1.ListPoliciesByOwnerResponse
}

func (f *fakePolicyService) ListPoliciesByOwner(_ context.Context, req *corev1.ListPoliciesByOwnerRequest) (*corev1.ListPoliciesByOwnerResponse, error) {
	f.got = req
	if f.resp != nil {
		return f.resp, nil
	}
	return &corev1.ListPoliciesByOwnerResponse{}, nil
}

// dialCore stands up an in-process gRPC server with whatever services the
// caller registers and returns a live client connection to it.
func dialCore(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 64)
	srv := grpc.NewServer()
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return conn
}

// TestCategoryRulePreviewerSendsDryRun is the central assertion:
// the preview does NOT reimplement a count, it calls's existing
// PurgeUserCategoryRules with dry_run=true — the form core's contract documents
// as mutating nothing, emitting no audit, and still returning what WOULD be
// removed. If dry_run were false this call would DELETE the account's grants
// while merely previewing a delete.
func TestCategoryRulePreviewerSendsDryRun(t *testing.T) {
	fake := &fakeGroupService{}
	conn := dialCore(t, func(s *grpc.Server) { corev1.RegisterCategoryServiceServer(s, fake) })

	prev := userdelete.NewGRPCCategoryRulePreviewer(corev1.NewCategoryServiceClient(conn))
	if _, err := prev.PreviewUserCategoryRules(context.Background(), "u-9"); err != nil {
		t.Fatalf("PreviewUserCategoryRules: %v", err)
	}
	if fake.got == nil {
		t.Fatal("the RPC was never called")
	}
	if !fake.got.GetDryRun() {
		t.Errorf("dry_run = false — previewing a delete would have DELETED the account's RACI grants")
	}
	if fake.got.GetUserId() != "u-9" {
		t.Errorf("user_id = %q, want the previewed account", fake.got.GetUserId())
	}
	// actor_user_id exists so core can attribute the purge in its audit trail.
	// A dry run writes no audit, so sending an actor would put an admin's id on
	// a record of something that did not happen.
	if got := fake.got.GetActorUserId(); got != "" {
		t.Errorf("actor_user_id = %q, want empty on a read-only dry run", got)
	}
}

// TestCategoryRulePreviewerMapsRules pins that the adapter reads the per-rule
// rows core returns. The MUTATING adapter deliberately drops them (the delete
// path only needs the count); a preview needs the rows, because "3 grants will
// be removed" is not actionable and "author on this category" is.
func TestCategoryRulePreviewerMapsRules(t *testing.T) {
	fake := &fakeGroupService{resp: &corev1.PurgeUserCategoryRulesResponse{
		RemovedRules:        2,
		AffectedCategoryIds: []string{"cat-a", "cat-b"},
		Rules: []*corev1.RemovedCategoryRule{
			{CategoryId: "cat-a", Rule: &corev1.CategoryRule{
				SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
				SubjectRef:  "u-9",
				Author:      corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				Approve:     corev1.GrantEffect_GRANT_EFFECT_ALLOW,
				Read:        corev1.GrantEffect_GRANT_EFFECT_DENY,
			}},
			{CategoryId: "cat-b", Rule: &corev1.CategoryRule{
				SubjectKind: corev1.RuleSubjectKind_RULE_SUBJECT_KIND_USER,
				SubjectRef:  "u-9",
				Ack:         corev1.GrantEffect_GRANT_EFFECT_ALLOW,
			}},
		},
	}}
	conn := dialCore(t, func(s *grpc.Server) { corev1.RegisterCategoryServiceServer(s, fake) })

	got, err := userdelete.NewGRPCCategoryRulePreviewer(corev1.NewCategoryServiceClient(conn)).
		PreviewUserCategoryRules(context.Background(), "u-9")
	if err != nil {
		t.Fatalf("PreviewUserCategoryRules: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 grants, got %d: %+v", len(got), got)
	}
	if got[0].CategoryID != "cat-a" {
		t.Errorf("first grant category = %q, want cat-a", got[0].CategoryID)
	}
	// ALLOW is a grant the account holds; DENY is not, so `read` must not be
	// listed as a role the delete takes away.
	want := []string{"author", "approve"}
	if len(got[0].Roles) != len(want) {
		t.Fatalf("roles = %v, want %v (a DENY is not a held grant)", got[0].Roles, want)
	}
	for i := range want {
		if got[0].Roles[i] != want[i] {
			t.Errorf("roles = %v, want %v", got[0].Roles, want)
		}
	}
	if len(got[1].Roles) != 1 || got[1].Roles[0] != "ack" {
		t.Errorf("second grant roles = %v, want [ack]", got[1].Roles)
	}
}

// TestCategoryRulePreviewerFallsBackToCounts: if core reports a non-zero
// removed_rules but no per-rule rows, the preview must still report the right
// NUMBER of grants. Silently showing zero would tell the admin no grants are at
// risk, which is the failure mode.
func TestCategoryRulePreviewerFallsBackToCounts(t *testing.T) {
	fake := &fakeGroupService{resp: &corev1.PurgeUserCategoryRulesResponse{
		RemovedRules:        2,
		AffectedCategoryIds: []string{"cat-a", "cat-b"},
	}}
	conn := dialCore(t, func(s *grpc.Server) { corev1.RegisterCategoryServiceServer(s, fake) })

	got, err := userdelete.NewGRPCCategoryRulePreviewer(corev1.NewCategoryServiceClient(conn)).
		PreviewUserCategoryRules(context.Background(), "u-9")
	if err != nil {
		t.Fatalf("PreviewUserCategoryRules: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 grants from the category-id fallback, got %d", len(got))
	}
}

// TestOwnedPolicyListerIncludesRetired: a retired policy still has an
// owner_user_id, so a delete still orphans it. Excluding retired policies would
// under-report the blast radius.
func TestOwnedPolicyListerIncludesRetired(t *testing.T) {
	fake := &fakePolicyService{resp: &corev1.ListPoliciesByOwnerResponse{
		Policies: []*corev1.Policy{
			{Id: "p-1", Number: "IT-001", Title: "Access Control"},
			{Id: "p-2", Number: "IT-009", Title: "Old Thing", RetiredAt: "2026-01-02T00:00:00Z"},
		},
	}}
	conn := dialCore(t, func(s *grpc.Server) { corev1.RegisterPolicyServiceServer(s, fake) })

	got, err := userdelete.NewGRPCOwnedPolicyLister(corev1.NewPolicyServiceClient(conn)).
		ListPoliciesByOwner(context.Background(), "u-9")
	if err != nil {
		t.Fatalf("ListPoliciesByOwner: %v", err)
	}
	if fake.got == nil {
		t.Fatal("the RPC was never called")
	}
	if !fake.got.GetIncludeRetired() {
		t.Errorf("include_retired = false — a retired policy is still orphaned by the delete")
	}
	if fake.got.GetOwnerUserId() != "u-9" {
		t.Errorf("owner_user_id = %q, want the previewed account", fake.got.GetOwnerUserId())
	}
	if len(got) != 2 {
		t.Fatalf("want 2 policies, got %d", len(got))
	}
	if got[0].Retired {
		t.Errorf("p-1 has an empty retired_at and must not be marked retired")
	}
	if !got[1].Retired {
		t.Errorf("p-2 has a retired_at stamp and must be marked retired")
	}
	if got[1].Number != "IT-009" || got[1].Title != "Old Thing" {
		t.Errorf("policy fields lost in mapping: %+v", got[1])
	}
}
