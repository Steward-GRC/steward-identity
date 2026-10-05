// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// newAdminHandlerWithFakePublisher returns an AdminHandler wired to a fresh
// testcontainers store and a fake SSO event publisher, so access-granted
// emission on the admin grant RPCs can be asserted without a broker. Mirrors
// newReadHandlerWithFakePublisher (sso_events_test.go).
func newAdminHandlerWithFakePublisher(t *testing.T) (*handlers.AdminHandler, *store.Store, *fakeSSOPublisher) {
	t.Helper()
	s := newTestStore(t)
	if s == nil {
		return nil, nil, nil
	}
	pub := &fakeSSOPublisher{}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth).WithSSOEventPublisher(pub)
	return h, s, pub
}

// seedAdminActor provisions a JIT user to use as the acting admin's user id.
// The grant RPCs record actorUUIDPtr(actor) as a real FK (group_membership /
// user_roles' granted_by columns), so the calling context's user id must
// resolve to an existing row — a random uuid.NewString() 404s at the FK.
// Mirrors TestAdminGrantRoleWithAdminClaim's admin, err := s.JITProvision(...)
// pattern in admin_test.go, just factored out for this file's five tests.
func seedAdminActor(t *testing.T, s *store.Store) string {
	t.Helper()
	admin, err := s.JITProvision(context.Background(), "sub-actor-"+uuid.NewString(), "admin@example.org", "Admin")
	require.NoError(t, err)
	return admin.ID.String()
}

// TestGrant_EmitsAccessGranted is the brief's core Task-33 test: granting a
// group to a JIT user publishes sso.access_granted.
//
// NOTE: like spcert_rpc_test.go's TestGetSPCertificate_PublicOnly, this
// repo's adminCtx takes a userID (unlike the brief's idealized adminCtx());
// adminCtx(seedAdminActor(...)) is the equivalent authorized context (the
// actor id is a real FK target, so it must resolve to a seeded user, unlike
// a bare uuid.NewString()). Similarly CreateGroup's actor param is
// *uuid.UUID (nil here), not the brief's "".
func TestGrant_EmitsAccessGranted(t *testing.T) {
	h, s, pub := newAdminHandlerWithFakePublisher(t)
	ctx := context.Background()
	actor := seedAdminActor(t, s)
	u, err := s.JITProvision(ctx, "sub-a", "a@example.org", "A")
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Engineering", uuid.Nil, nil, nil, "t")
	require.NoError(t, err)

	_, err = h.AddUserToGroup(adminCtx(actor), &identityv1.AddUserToGroupRequest{
		UserId: u.ID.String(), GroupId: g.ID.String(),
	})
	require.NoError(t, err)

	ev := pub.Find("sso.access_granted")
	require.NotNil(t, ev)
	require.Equal(t, u.ID.String(), ev.Vars["userId"])
	require.Equal(t, "a@example.org", ev.Vars["email"])
	require.Equal(t, "Engineering", ev.Vars["grant"])
	require.Equal(t, []string{"Engineering"}, ev.Vars["groups"])
}

// TestGrant_NoOpRegrantDoesNotDoubleEmit: re-granting a group the user
// already has is a store-level no-op (AddUserToGroup is idempotent) and must
// not fire a second access-granted notification.
func TestGrant_NoOpRegrantDoesNotDoubleEmit(t *testing.T) {
	h, s, pub := newAdminHandlerWithFakePublisher(t)
	ctx := context.Background()
	actor := seedAdminActor(t, s)
	u, err := s.JITProvision(ctx, "sub-b", "b@example.org", "B")
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Finance", uuid.Nil, nil, nil, "t")
	require.NoError(t, err)

	req := &identityv1.AddUserToGroupRequest{UserId: u.ID.String(), GroupId: g.ID.String()}
	_, err = h.AddUserToGroup(adminCtx(actor), req)
	require.NoError(t, err)
	_, err = h.AddUserToGroup(adminCtx(actor), req)
	require.NoError(t, err)

	require.Equal(t, 1, pub.Count("sso.access_granted"), "re-grant of an existing membership must not double-emit")
}

// TestGrant_NoEmailSkipsEmit: a user with no resolvable email (empty string)
// must not produce an access-granted event — and, critically, must not panic
// or fail the grant RPC.
func TestGrant_NoEmailSkipsEmit(t *testing.T) {
	h, s, pub := newAdminHandlerWithFakePublisher(t)
	ctx := context.Background()
	actor := seedAdminActor(t, s)
	u, err := s.JITProvision(ctx, "sub-noemail", "", "NoEmail")
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Ops", uuid.Nil, nil, nil, "t")
	require.NoError(t, err)

	_, err = h.AddUserToGroup(adminCtx(actor), &identityv1.AddUserToGroupRequest{
		UserId: u.ID.String(), GroupId: g.ID.String(),
	})
	require.NoError(t, err, "grant must succeed even when the notification is skipped")
	require.Nil(t, pub.Find("sso.access_granted"), "no email to notify — the emit must be skipped")
}

// TestGrantRole_EmitsAccessGranted: granting a scoped role to a JIT user
// publishes sso.access_granted with a human-readable role+category grant
// description.
func TestGrantRole_EmitsAccessGranted(t *testing.T) {
	h, s, pub := newAdminHandlerWithFakePublisher(t)
	ctx := context.Background()
	actor := seedAdminActor(t, s)
	u, err := s.JITProvision(ctx, "sub-c", "c@example.org", "C")
	require.NoError(t, err)

	_, err = h.GrantRole(adminCtx(actor), &identityv1.GrantRoleRequest{
		UserId: u.ID.String(), Role: "author", Category: "IT Security",
	})
	require.NoError(t, err)

	ev := pub.Find("sso.access_granted")
	require.NotNil(t, ev)
	require.Equal(t, "c@example.org", ev.Vars["email"])
	require.Equal(t, "author (IT Security)", ev.Vars["grant"])
}

// TestGrantRole_NoOpDoesNotDoubleEmit: re-granting a role the user already
// holds must not fire a second access-granted notification.
func TestGrantRole_NoOpDoesNotDoubleEmit(t *testing.T) {
	h, s, pub := newAdminHandlerWithFakePublisher(t)
	ctx := context.Background()
	actor := seedAdminActor(t, s)
	u, err := s.JITProvision(ctx, "sub-d", "d@example.org", "D")
	require.NoError(t, err)

	req := &identityv1.GrantRoleRequest{UserId: u.ID.String(), Role: "author", Category: "IT Security"}
	_, err = h.GrantRole(adminCtx(actor), req)
	require.NoError(t, err)
	_, err = h.GrantRole(adminCtx(actor), req)
	require.NoError(t, err)

	require.Equal(t, 1, pub.Count("sso.access_granted"), "re-grant of a role already held must not double-emit")
}
