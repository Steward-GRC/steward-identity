// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/workloadauth"
)

// newRootUser provisions a user, makes them a root admin and gives them
// site-admin in the test role source.
func newRootUser(t *testing.T, s *store.Store, sub, email string) store.User {
	t.Helper()
	u, err := s.JITProvision(context.Background(), sub, email, "Root "+sub)
	require.NoError(t, err)
	u, err = s.GrantRoot(context.Background(), u.ID, nil, "test")
	require.NoError(t, err)
	return u
}

func reportingCtx() context.Context {
	return workloadauth.ContextWithGrant(context.Background(), workloadauth.Grant{
		Caller: workloadauth.Caller{Name: "reporting"}, Access: workloadauth.Self,
	})
}

type hardResetFixture struct {
	s    *store.Store
	h    *handlers.AdminHandler
	a, b store.User
	now  time.Time
}

func newHardResetFixture(t *testing.T) *hardResetFixture {
	t.Helper()
	s := newTestStore(t)
	f := &hardResetFixture{s: s, now: time.Now().UTC()}
	f.a = newRootUser(t, s, "kc-hr-a", "hra@example.example.org")
	f.b = newRootUser(t, s, "kc-hr-b", "hrb@example.example.org")
	f.h = handlers.NewAdminHandler(s, testAdminAuth()).
		WithOTP(&fakeSender{}, zerolog.Nop(), true).
		WithHardReset(24*time.Hour, time.Hour, func() time.Time { return f.now })
	return f
}

func TestHardReset_TwoRootAdminsAndTheModuleService(t *testing.T) {
	f := newHardResetFixture(t)

	req, err := f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "start over"})
	require.NoError(t, err)
	r := req.GetRequest()
	require.Equal(t, identityv1.HardResetState_HARD_RESET_STATE_PENDING, r.GetState())
	require.Equal(t, f.a.ID.String(), r.GetRequestedBy())
	require.Equal(t, f.now.Add(24*time.Hour).Format(time.RFC3339), r.GetExpiresAt())

	_, err = f.h.ApproveHardReset(adminCtx(f.a.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: r.GetId()})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "the requester can't approve their own request")

	appr, err := f.h.ApproveHardReset(adminCtx(f.b.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: r.GetId()})
	require.NoError(t, err)
	require.Equal(t, identityv1.HardResetState_HARD_RESET_STATE_APPROVED, appr.GetRequest().GetState())
	require.Equal(t, f.b.ID.String(), appr.GetRequest().GetApprovedBy())
	require.Equal(t, f.now.Add(time.Hour).Format(time.RFC3339), appr.GetRequest().GetApprovalExpiresAt())

	used, err := f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: r.GetId(), Module: "compliance"})
	require.NoError(t, err)
	require.Equal(t, identityv1.HardResetState_HARD_RESET_STATE_CONSUMED, used.GetRequest().GetState())
	require.Equal(t, "reporting", used.GetRequest().GetConsumedBy())
	require.Equal(t, f.a.ID.String(), used.GetRequest().GetRequestedBy())
	require.Equal(t, f.b.ID.String(), used.GetRequest().GetApprovedBy())

	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: r.GetId(), Module: "compliance"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "an approval is used once")

	list, err := f.h.ListHardResetRequests(adminCtx(f.b.ID.String()), &identityv1.ListHardResetRequestsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetRequests(), 1)
}

func TestHardReset_Refusals(t *testing.T) {
	f := newHardResetFixture(t)
	ctx := context.Background()
	plain, err := f.s.JITProvision(ctx, "kc-hr-plain", "hrplain@example.example.org", "Plain")
	require.NoError(t, err)

	_, err = f.h.RequestHardReset(adminCtx(plain.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "x"})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "a site-admin who isn't root can't request")

	_, err = f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "everything", Reason: "x"})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "only known modules")
	_, err = f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance"})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "a reason is required")

	claimsCtx(f.a.ID.String(), []string{"site-admin"})
	_, err = f.h.RequestHardReset(actingAsCtx(f.a.ID.String(), f.b.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "x"})
	require.Error(t, err, "refused during act-as")

	r, err := f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "x"})
	require.NoError(t, err)
	id := r.GetRequest().GetId()

	_, err = f.h.RequestHardReset(adminCtx(f.b.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "y"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "one open request per module")

	claimsCtx(f.b.ID.String(), []string{"site-admin"})
	_, err = f.h.ApproveHardReset(actingAsCtx(f.b.ID.String(), f.a.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.Error(t, err, "refused during act-as")

	_, err = f.h.CancelHardReset(adminCtx(f.b.ID.String()), &identityv1.CancelHardResetRequest{RequestId: id})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "only the requester cancels")

	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: id, Module: "compliance"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "an unapproved request can't be used")

	c, err := f.h.CancelHardReset(adminCtx(f.a.ID.String()), &identityv1.CancelHardResetRequest{RequestId: id})
	require.NoError(t, err)
	require.Equal(t, identityv1.HardResetState_HARD_RESET_STATE_CANCELLED, c.GetRequest().GetState())
}

func TestHardReset_ApprovalWindowsAreConfigurable(t *testing.T) {
	f := newHardResetFixture(t)
	r, err := f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "x"})
	require.NoError(t, err)
	_, err = f.h.ApproveHardReset(adminCtx(f.b.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: r.GetRequest().GetId()})
	require.NoError(t, err)

	f.now = f.now.Add(61 * time.Minute)
	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: r.GetRequest().GetId(), Module: "compliance"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "the approval lapses after HARD_RESET_APPROVAL_TTL")

	list, err := f.h.ListHardResetRequests(adminCtx(f.a.ID.String()), &identityv1.ListHardResetRequestsRequest{Module: "compliance"})
	require.NoError(t, err)
	require.Equal(t, identityv1.HardResetState_HARD_RESET_STATE_EXPIRED, list.GetRequests()[0].GetState())
}

func TestConsumeHardReset_OnlyAsAService(t *testing.T) {
	f := newHardResetFixture(t)
	_, err := f.h.ConsumeHardReset(adminCtx(f.a.ID.String()), &identityv1.ConsumeHardResetRequest{RequestId: "00000000-0000-0000-0000-000000000000", Module: "compliance"})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "an admin can't redeem a hard reset; the module's service does")
}

func TestRevokeRoot_TheLastRootAdminKeepsIt(t *testing.T) {
	s := newTestStore(t)
	a := newRootUser(t, s, "kc-rr-a", "rra@example.example.org")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithOTP(&fakeSender{}, zerolog.Nop(), true)

	_, err := h.RevokeRoot(adminCtx(a.ID.String()), &identityv1.RevokeRootRequest{UserId: a.ID.String(), Otp: stepUpCodeFor(t, s, a.ID.String())})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestGrantRoot_RootOnlyAndNeverDuringActAs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := newRootUser(t, s, "kc-gr-a", "gra@example.example.org")
	admin, err := s.JITProvision(ctx, "kc-gr-admin", "gradmin@example.example.org", "Admin")
	require.NoError(t, err)
	target, err := s.JITProvision(ctx, "kc-gr-t", "grt@example.example.org", "Target")
	require.NoError(t, err)
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithOTP(&fakeSender{}, zerolog.Nop(), true)

	_, err = h.GrantRoot(adminCtx(admin.ID.String()), &identityv1.GrantRootRequest{UserId: target.ID.String(), Otp: stepUpCodeFor(t, s, admin.ID.String())})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "a site-admin who isn't root can't grant root")

	claimsCtx(target.ID.String(), []string{"site-admin"})
	_, err = h.GrantRoot(actingAsCtx(target.ID.String(), a.ID.String()), &identityv1.GrantRootRequest{UserId: target.ID.String(), Otp: stepUpCodeFor(t, s, a.ID.String())})
	require.Error(t, err, "refused during act-as")

	got, err := s.GetUser(ctx, target.ID)
	require.NoError(t, err)
	require.False(t, got.IsRoot)
}
