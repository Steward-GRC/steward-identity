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
)

// TestListOrganizations_ReturnsCreatedOrg: an org created via AddOrganization
// shows up in ListOrganizations, with its domain and connection_id.
func TestListOrganizations_ReturnsCreatedOrg(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	addResp, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "ListMe", Domain: "listme.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)
	wantConnID := addResp.GetOrganization().GetConnectionId()

	listResp, err := h.ListOrganizations(adminCtx(uuid.NewString()), &identityv1.ListOrganizationsRequest{})
	require.NoError(t, err)

	var found *identityv1.Organization
	for _, o := range listResp.GetOrganizations() {
		if o.GetDomain() == "listme.example.net" {
			found = o
			break
		}
	}
	require.NotNil(t, found, "expected listme.example.net in ListOrganizations")
	require.Equal(t, wantConnID, found.GetConnectionId())
}

// TestListOrganizations_RequiresAuth: unauthenticated callers are rejected
// before any DB work.
func TestListOrganizations_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.ListOrganizations(noopCtx(), &identityv1.ListOrganizationsRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestGetOrganization_ReturnsCreatedOrg: GetOrganization returns the org
// created via AddOrganization by domain.
func TestGetOrganization_ReturnsCreatedOrg(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	addResp, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "GetMe", Domain: "getme.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)

	getResp, err := h.GetOrganization(adminCtx(uuid.NewString()), &identityv1.GetOrganizationRequest{Domain: "getme.example.net"})
	require.NoError(t, err)
	require.Equal(t, "getme.example.net", getResp.GetOrganization().GetDomain())
	require.Equal(t, addResp.GetOrganization().GetConnectionId(), getResp.GetOrganization().GetConnectionId())
}

// TestGetOrganization_UnknownDomainNotFound: a domain that was never
// registered returns NotFound.
func TestGetOrganization_UnknownDomainNotFound(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.GetOrganization(adminCtx(uuid.NewString()), &identityv1.GetOrganizationRequest{Domain: "never-registered.example.net"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

// TestGetOrganization_RequiresAuth: unauthenticated callers are rejected
// before any DB work.
func TestGetOrganization_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.GetOrganization(noopCtx(), &identityv1.GetOrganizationRequest{Domain: "getme.example.net"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestDeleteOrganization_RemovesRoutingAndConnection is the load-bearing
// Task-21 invariant: after DeleteOrganization, the domain no longer resolves
// (GetOrganization -> NotFound), DiscoverMethod no longer routes it to sso,
// and the underlying idp_connections row is gone too.
func TestDeleteOrganization_RemovesRoutingAndConnection(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	addResp, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "DeleteMe", Domain: "deleteme.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)
	connID := addResp.GetOrganization().GetConnectionId()

	delResp, err := h.DeleteOrganization(adminCtx(uuid.NewString()), &identityv1.DeleteOrganizationRequest{Domain: "deleteme.example.net"})
	require.NoError(t, err)
	require.Equal(t, "deleteme.example.net", delResp.GetDomain())

	_, err = h.GetOrganization(adminCtx(uuid.NewString()), &identityv1.GetOrganizationRequest{Domain: "deleteme.example.net"})
	require.Equal(t, codes.NotFound, status.Code(err))

	res, derr := s.DiscoverMethod(context.Background(), "deleteme.example.net")
	if derr == nil {
		require.NotEqual(t, "sso", res.Method, "deleted domain must never route to sso")
	}

	id, perr := uuid.Parse(connID)
	require.NoError(t, perr)
	_, cerr := s.GetIdPConnection(context.Background(), id)
	require.Error(t, cerr, "expected the idp connection row to be removed too")
}

// TestDeleteOrganization_EnabledRejected: a LIVE (enabled) org cannot be
// deleted — it must be disabled first, so an in-use connection is never torn
// out from under active sessions. A disabled org deletes fine (covered by
// TestDeleteOrganization_RemovesRoutingAndConnection).
func TestDeleteOrganization_EnabledRejected(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	addResp, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "LiveOrg", Domain: "liveorg.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)
	id, perr := uuid.Parse(addResp.GetOrganization().GetConnectionId())
	require.NoError(t, perr)

	// Force the connection live, then attempt delete → must be refused.
	require.NoError(t, s.SetIdPConnectionEnabled(context.Background(), id, true))
	_, err = h.DeleteOrganization(adminCtx(uuid.NewString()), &identityv1.DeleteOrganizationRequest{Domain: "liveorg.example.net"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "must refuse deleting a live org")

	// A refused delete must leave the org fully intact.
	_, gerr := h.GetOrganization(adminCtx(uuid.NewString()), &identityv1.GetOrganizationRequest{Domain: "liveorg.example.net"})
	require.NoError(t, gerr, "a refused delete must not tear anything down")
}

// TestDeleteOrganization_UnknownDomainNotFound: deleting a domain that was
// never registered returns NotFound rather than silently succeeding.
func TestDeleteOrganization_UnknownDomainNotFound(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.DeleteOrganization(adminCtx(uuid.NewString()), &identityv1.DeleteOrganizationRequest{Domain: "never-registered.example.net"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

// TestDeleteOrganization_RequiresAuth: unauthenticated callers are rejected
// before any DB work.
func TestDeleteOrganization_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.DeleteOrganization(noopCtx(), &identityv1.DeleteOrganizationRequest{Domain: "deleteme.example.net"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestUpdateIdPConnection_TogglesJitAndLocal/#27): UpdateIdPConnection
// flips jit_enabled / allow_local and the change is reflected in the response
// and a subsequent GetOrganization. A nil (unset) toggle leaves the other
// untouched, and the RPC is no longer Unimplemented.
func TestUpdateIdPConnection_TogglesJitAndLocal(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "Toggle Org", Domain: "toggleorg.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)

	// Defaults: jit on, local off.
	got, err := h.GetOrganization(adminCtx(uuid.NewString()), &identityv1.GetOrganizationRequest{Domain: "toggleorg.example.net"})
	require.NoError(t, err)
	require.True(t, got.GetOrganization().GetJitEnabled(), "jit_enabled defaults true")
	require.False(t, got.GetOrganization().GetAllowLocal(), "allow_local defaults false")

	// Turn JIT off and local on in one call.
	jitOff, allowOn := false, true
	upd, err := h.UpdateIdPConnection(adminCtx(uuid.NewString()), &identityv1.UpdateIdPConnectionRequest{
		Domain: "toggleorg.example.net", JitEnabled: &jitOff, AllowLocal: &allowOn,
	})
	require.NoError(t, err, "UpdateIdPConnection must be implemented, not Unimplemented")
	require.False(t, upd.GetOrganization().GetJitEnabled())
	require.True(t, upd.GetOrganization().GetAllowLocal())

	// An update that sets only allow_local must leave jit_enabled unchanged.
	allowOff := false
	upd2, err := h.UpdateIdPConnection(adminCtx(uuid.NewString()), &identityv1.UpdateIdPConnectionRequest{
		Domain: "toggleorg.example.net", AllowLocal: &allowOff,
	})
	require.NoError(t, err)
	require.False(t, upd2.GetOrganization().GetJitEnabled(), "unset jit_enabled must be left as-is")
	require.False(t, upd2.GetOrganization().GetAllowLocal())

	// Persisted.
	after, err := h.GetOrganization(adminCtx(uuid.NewString()), &identityv1.GetOrganizationRequest{Domain: "toggleorg.example.net"})
	require.NoError(t, err)
	require.False(t, after.GetOrganization().GetJitEnabled())
	require.False(t, after.GetOrganization().GetAllowLocal())
}

// TestUpdateIdPConnection_RequiresAuth: unauthenticated callers are rejected
// before any DB work.
func TestUpdateIdPConnection_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.UpdateIdPConnection(noopCtx(), &identityv1.UpdateIdPConnectionRequest{Domain: "toggleorg.example.net"})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}
