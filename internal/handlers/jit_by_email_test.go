// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// newReadHandlerWithFakePublisher wires a ReadHandler to a fresh test store and
// a capturing SSO event publisher so the JIT-by-email welcome / access-granted
// emissions can be asserted without a broker.
func newJITReadHandler(t *testing.T) (*handlers.ReadHandler, *store.Store, *fakeSSOPublisher) {
	t.Helper()
	s := newTestStore(t)
	pub := &fakeSSOPublisher{}
	return handlers.NewReadHandler(s).WithSSOEventPublisher(pub), s, pub
}

// TestJitProvisionByEmail_NewCreatesAndEmitsWelcome: a first-seen email is
// provisioned as a federated user (empty subject, names set) and emits the
// sso.account_provisioned welcome — with NO "pending" var (a groupless
// federated user has baseline Everyone access and can sign in immediately).
func TestJitProvisionByEmail_NewCreatesAndEmitsWelcome(t *testing.T) {
	h, _, pub := newJITReadHandler(t)
	ctx := context.Background()

	resp, err := h.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email: "grace@example.org", FirstName: "Grace", LastName: "Example",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	require.Equal(t, "grace@example.org", resp.GetUser().GetEmail())
	require.Equal(t, "Grace", resp.GetUser().GetFirstName())
	require.Equal(t, "Example", resp.GetUser().GetLastName())
	require.True(t, resp.GetUser().GetEnabled())
	require.False(t, resp.GetUser().GetIsRoot())

	ev := pub.Find("sso.account_provisioned")
	require.NotNil(t, ev, "a fresh JIT-by-email create must emit the welcome")
	require.Equal(t, "grace@example.org", ev.Vars["email"])
	require.NotContains(t, ev.Vars, "pending", "the retired pending flag must not be emitted")
}

// TestJitProvisionByEmail_ExistingNoDupNoWelcome: an email already owned by a
// platform user returns that user and does NOT re-emit the welcome.
func TestJitProvisionByEmail_ExistingNoDupNoWelcome(t *testing.T) {
	h, s, pub := newJITReadHandler(t)
	ctx := context.Background()

	existing, err := s.JITProvision(ctx, "kc-sub-existing", "existing@example.org", "Existing User")
	require.NoError(t, err)

	resp, err := h.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email: "existing@example.org", FirstName: "Ignored", LastName: "Ignored",
	})
	require.NoError(t, err)
	require.Equal(t, existing.ID.String(), resp.GetUser().GetId())
	require.Nil(t, pub.Find("sso.account_provisioned"), "an existing user must not re-emit the welcome")
}

// TestJitProvisionByEmail_AppliesGroupMappings: with an idp_alias + asserted
// groups, the connection's group mappings are applied to the newly provisioned
// user and sso.access_granted is emitted.
func TestJitProvisionByEmail_AppliesGroupMappings(t *testing.T) {
	h, s, pub := newJITReadHandler(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Engineering", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)
	_, err = s.AddIdPGroupMapping(ctx, conn.ID, "eng", g.ID)
	require.NoError(t, err)

	resp, err := h.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email: "mapped@example.org", FirstName: "Map", LastName: "Ped",
		ConnectionAlias: "example-org", IdpGroups: []string{"eng", "unmapped"},
	})
	require.NoError(t, err)
	require.Contains(t, resp.GetUser().GetGroups(), g.ID.String(),
		"the mapped IdP group must land the user in the platform group")

	ev := pub.Find("sso.access_granted")
	require.NotNil(t, ev)
	require.Equal(t, "mapped@example.org", ev.Vars["email"])
	require.Equal(t, []string{"Engineering"}, ev.Vars["groups"])
}

// TestJitProvisionByEmail_EmptyEmailInvalidArgument.
func TestJitProvisionByEmail_EmptyEmailInvalidArgument(t *testing.T) {
	h, _, _ := newJITReadHandler(t)
	_, err := h.JitProvisionByEmail(context.Background(), &identityv1.JitProvisionByEmailRequest{Email: "  "})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestJitProvisionByEmail_JitDisabledNewUserFailsClosed: when the
// connection named by idp_alias has jit_enabled=false, a first-seen email is
// NOT auto-created — the call fails closed with a coded PermissionDenied and no
// user row is written.
func TestJitProvisionByEmail_JitDisabledNewUserFailsClosed(t *testing.T) {
	h, s, pub := newJITReadHandler(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	require.True(t, conn.JitEnabled, "connections default to jit_enabled=true")
	jitOff := false
	require.NoError(t, s.SetIdPConnectionLoginToggles(ctx, conn.ID, &jitOff, nil))

	_, err = h.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email: "newbie@example.org", FirstName: "New", LastName: "Bie", ConnectionAlias: "example-org",
	})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "jit-disabled new user must fail closed")

	// No user was created, and no welcome fired.
	_, getErr := s.GetUserByEmail(ctx, "newbie@example.org")
	require.ErrorIs(t, getErr, store.ErrNotFound, "a jit-disabled fail-closed must not create a row")
	require.Nil(t, pub.Find("sso.account_provisioned"))
}

// TestJitProvisionByEmail_JitDisabledExistingUserLogsIn: an
// already-provisioned platform user still logs in through a jit_enabled=false
// connection — the flag only blocks new auto-creates. No duplicate welcome.
func TestJitProvisionByEmail_JitDisabledExistingUserLogsIn(t *testing.T) {
	h, s, pub := newJITReadHandler(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	jitOff := false
	require.NoError(t, s.SetIdPConnectionLoginToggles(ctx, conn.ID, &jitOff, nil))

	existing, err := s.JITProvision(ctx, "kc-sub-known", "known@example.org", "Known User")
	require.NoError(t, err)

	resp, err := h.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email: "known@example.org", ConnectionAlias: "example-org",
	})
	require.NoError(t, err, "an existing user must still log in with jit disabled")
	require.Equal(t, existing.ID.String(), resp.GetUser().GetId())
	require.Nil(t, pub.Find("sso.account_provisioned"), "existing user must not re-emit the welcome")
}
