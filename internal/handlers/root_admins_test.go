// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	workloadidentity "github.com/Bugs5382/go-workload-identity"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// execTestSQL runs a statement straight on the test database behind s.
func execTestSQL(t *testing.T, s *store.Store, sql string, args ...any) {
	t.Helper()
	v, ok := testDSNs.Load(s)
	require.True(t, ok, "store did not come from newTestStore")
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, v.(string))
	require.NoError(t, err)
	defer pool.Close()
	_, err = pool.Exec(ctx, sql, args...)
	require.NoError(t, err)
}

// newRootUser provisions a user and makes them the root admin with
// site-admin. It writes the rows directly, as the store has no way to add a
// second root.
func newRootUser(t *testing.T, s *store.Store, sub, email string) store.User {
	t.Helper()
	u, err := s.JITProvision(context.Background(), sub, email, "Root "+sub)
	require.NoError(t, err)
	execTestSQL(t, s, `UPDATE users SET is_root = true WHERE id = $1`, u.ID)
	execTestSQL(t, s, `INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '') ON CONFLICT DO NOTHING`, u.ID)
	u, err = s.GetUser(context.Background(), u.ID)
	require.NoError(t, err)
	return u
}

// cliCtx is a call from the admin CLI over mTLS: a verified SPIFFE peer and
// no forwarded user, so the call has no actor.
func cliCtx(t *testing.T) context.Context {
	t.Helper()
	u, err := url.Parse(testCLIID)
	require.NoError(t, err)
	state := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}

func reportingCtx() context.Context {
	return workloadidentity.ContextWithGrant(context.Background(), workloadidentity.Grant{
		Caller: workloadidentity.Caller{Name: "reporting"}, Access: workloadidentity.Self,
	})
}

type hardResetFixture struct {
	s    *store.Store
	h    *handlers.AdminHandler
	a, b store.User // a is the one root; b is an ordinary site-admin
	now  time.Time
}

// newSiteAdminUser provisions an ordinary account holding the global
// site-admin right, in the database and in the test claims.
func newSiteAdminUser(t *testing.T, s *store.Store, sub, email string) store.User {
	t.Helper()
	u, err := s.JITProvision(context.Background(), sub, email, "Admin "+sub)
	require.NoError(t, err)
	execTestSQL(t, s, `INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '') ON CONFLICT DO NOTHING`, u.ID)
	u, err = s.GetUser(context.Background(), u.ID)
	require.NoError(t, err)
	return u
}

func newHardResetFixture(t *testing.T) *hardResetFixture {
	t.Helper()
	s := newTestStore(t)
	f := &hardResetFixture{s: s, now: time.Now().UTC()}
	f.a = newRootUser(t, s, "kc-hr-a", "hra@example.example.org")
	f.b = newSiteAdminUser(t, s, "kc-hr-b", "hrb@example.example.org")
	f.h = handlers.NewAdminHandler(s, testAdminAuth()).
		WithOTP(&fakeSender{}, zerolog.Nop(), true).
		WithHardReset(24*time.Hour, time.Hour, func() time.Time { return f.now })
	return f
}

func (f *hardResetFixture) request(t *testing.T) string {
	t.Helper()
	r, err := f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "start over"})
	require.NoError(t, err)
	return r.GetRequest().GetId()
}

func TestHardReset_RootRequestsSiteAdminApprovesModuleServiceRedeems(t *testing.T) {
	f := newHardResetFixture(t)

	req, err := f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "start over"})
	require.NoError(t, err)
	r := req.GetRequest()
	require.Equal(t, identityv1.HardResetState_HARD_RESET_STATE_PENDING, r.GetState())
	require.Equal(t, f.a.ID.String(), r.GetRequestedBy())
	require.Equal(t, f.now.Add(24*time.Hour).Format(time.RFC3339), r.GetExpiresAt())

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
	require.NotEqual(t, used.GetRequest().GetRequestedBy(), used.GetRequest().GetApprovedBy(), "the contract reporting checks")

	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: r.GetId(), Module: "compliance"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "an approval is used once")

	for _, who := range []string{f.a.ID.String(), f.b.ID.String()} {
		list, err := f.h.ListHardResetRequests(adminCtx(who), &identityv1.ListHardResetRequestsRequest{})
		require.NoError(t, err, "root and a site-admin can both list")
		require.Len(t, list.GetRequests(), 1)
	}
}

func TestHardReset_SamePersonRefused(t *testing.T) {
	f := newHardResetFixture(t)
	id := f.request(t)
	_, err := f.h.ApproveHardReset(adminCtx(f.a.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "root can't approve its own request")

	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: id, Module: "compliance"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "nothing is approved, so nothing redeems")
}

func TestHardReset_NonAdminApproverRefused(t *testing.T) {
	f := newHardResetFixture(t)
	id := f.request(t)
	plain, err := f.s.JITProvision(context.Background(), "kc-hr-plain", "hrplain@example.example.org", "Plain")
	require.NoError(t, err)

	// A stale or forged claim that says site-admin is not enough: the database decides.
	_, err = f.h.ApproveHardReset(adminCtx(plain.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	// Without the claim the caller is refused before the store.
	_, err = f.h.ApproveHardReset(claimsCtx(plain.ID.String(), []string{"author"}), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: id, Module: "compliance"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestHardReset_DisabledApproverRefused(t *testing.T) {
	f := newHardResetFixture(t)
	id := f.request(t)
	_, err := f.s.SetEnabled(context.Background(), f.b.ID, false, nil, "test")
	require.NoError(t, err)

	_, err = f.h.ApproveHardReset(adminCtx(f.b.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "a disabled account can't approve, whatever its session says")
}

func TestHardReset_ExpiredRefused(t *testing.T) {
	f := newHardResetFixture(t)
	id := f.request(t)

	f.now = f.now.Add(25 * time.Hour)
	_, err := f.h.ApproveHardReset(adminCtx(f.b.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "an unapproved request lapses after HARD_RESET_REQUEST_TTL")

	id = f.request(t)
	_, err = f.h.ApproveHardReset(adminCtx(f.b.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.NoError(t, err)
	f.now = f.now.Add(61 * time.Minute)
	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: id, Module: "compliance"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "the approval lapses after HARD_RESET_APPROVAL_TTL")

	list, err := f.h.ListHardResetRequests(adminCtx(f.a.ID.String()), &identityv1.ListHardResetRequestsRequest{Module: "compliance"})
	require.NoError(t, err)
	require.Equal(t, identityv1.HardResetState_HARD_RESET_STATE_EXPIRED, list.GetRequests()[0].GetState())
}

func TestHardReset_RedeemOnceOnly(t *testing.T) {
	f := newHardResetFixture(t)
	id := f.request(t)
	_, err := f.h.ApproveHardReset(adminCtx(f.b.ID.String()), &identityv1.ApproveHardResetRequest{RequestId: id})
	require.NoError(t, err)

	_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: id, Module: "compliance"})
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = f.h.ConsumeHardReset(reportingCtx(), &identityv1.ConsumeHardResetRequest{RequestId: id, Module: "compliance"})
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
	}
}

func TestHardReset_Refusals(t *testing.T) {
	f := newHardResetFixture(t)

	_, err := f.h.RequestHardReset(adminCtx(f.b.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "x"})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "a site-admin who isn't root can't request")

	_, err = f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "everything", Reason: "x"})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "only known modules")
	_, err = f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance"})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "a reason is required")

	claimsCtx(f.a.ID.String(), []string{"site-admin"})
	_, err = f.h.RequestHardReset(actingAsCtx(f.a.ID.String(), f.b.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "x"})
	require.Error(t, err, "refused during act-as")

	id := f.request(t)

	_, err = f.h.RequestHardReset(adminCtx(f.a.ID.String()), &identityv1.RequestHardResetRequest{Module: "compliance", Reason: "y"})
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

func TestHardReset_ListNeedsRootOrSiteAdmin(t *testing.T) {
	f := newHardResetFixture(t)
	plain, err := f.s.JITProvision(context.Background(), "kc-hr-plain", "hrplain@example.example.org", "Plain")
	require.NoError(t, err)
	_, err = f.h.ListHardResetRequests(adminCtx(plain.ID.String()), &identityv1.ListHardResetRequestsRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestConsumeHardReset_OnlyAsAService(t *testing.T) {
	f := newHardResetFixture(t)
	_, err := f.h.ConsumeHardReset(adminCtx(f.a.ID.String()), &identityv1.ConsumeHardResetRequest{RequestId: "00000000-0000-0000-0000-000000000000", Module: "compliance"})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "an admin can't redeem a hard reset; the module's service does")
}

func TestTransferRoot_RootOnlyNeverDuringActAsNeverWithoutActor(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a := newRootUser(t, s, "kc-gr-a", "gra@example.example.org")
	admin, err := s.JITProvision(ctx, "kc-gr-admin", "gradmin@example.example.org", "Admin")
	require.NoError(t, err)
	target, err := s.JITProvision(ctx, "kc-gr-t", "grt@example.example.org", "Target")
	require.NoError(t, err)
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithOTP(&fakeSender{}, zerolog.Nop(), true)

	_, err = h.TransferRoot(adminCtx(admin.ID.String()), &identityv1.TransferRootRequest{ToUserId: target.ID.String(), Otp: stepUpCodeFor(t, s, admin.ID.String())})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "a site-admin who isn't root can't transfer root")

	claimsCtx(target.ID.String(), []string{"site-admin"})
	_, err = h.TransferRoot(actingAsCtx(target.ID.String(), a.ID.String()), &identityv1.TransferRootRequest{ToUserId: target.ID.String(), Otp: stepUpCodeFor(t, s, a.ID.String())})
	require.Error(t, err, "refused during act-as")

	// The CLI and mTLS path has no actor and so cannot transfer.
	_, err = h.TransferRoot(cliCtx(t), &identityv1.TransferRootRequest{ToUserId: target.ID.String(), Otp: "000000"})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "no actor")

	got, err := s.GetUser(ctx, target.ID)
	require.NoError(t, err)
	require.False(t, got.IsRoot)
	still, err := s.GetUser(ctx, a.ID)
	require.NoError(t, err)
	require.True(t, still.IsRoot)
}
