// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// TestActivate_RequiresBothGates is the load-bearing case: activation
// is rejected until BOTH the domain-verified and IdP-test-passed gates are
// satisfied, and succeeds once they both are.
//
// NOTE: GetOrganization doesn't exist yet, so unlike the brief's
// idealized snippet, the connection_id is read directly off the store
// (s.GetSSODomain) rather than via a handler RPC.
func TestActivate_RequiresBothGates(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "DS", Domain: "ds.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)

	_, err = h.ActivateOrganization(adminCtx(uuid.NewString()), &identityv1.ActivateOrganizationRequest{Domain: "ds.example.net"})
	require.Error(t, err) // neither gate passed
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	d, gerr := s.GetSSODomain(context.Background(), "ds.example.net")
	require.NoError(t, gerr)
	require.NotNil(t, d.ConnectionID)
	connID := d.ConnectionID.String()

	require.NoError(t, s.MarkDomainVerified(context.Background(), "ds.example.net", time.Now()))
	_, err = h.RecordIdPTestResult(adminCtx(uuid.NewString()), &identityv1.RecordIdPTestResultRequest{
		ConnectionId: connID, Success: true,
	})
	require.NoError(t, err)

	resp, err := h.ActivateOrganization(adminCtx(uuid.NewString()), &identityv1.ActivateOrganizationRequest{Domain: "ds.example.net"})
	require.NoError(t, err) // both gates now pass
	require.True(t, resp.GetOrganization().GetEnabled())
	require.True(t, resp.GetOrganization().GetVerified())
	require.True(t, resp.GetOrganization().GetTestPassed())
}

// TestActivate_OnlyVerifiedRejected: the domain-verified gate alone is not
// enough — no passed IdP test means activation must still be rejected.
func TestActivate_OnlyVerifiedRejected(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "OnlyVerified", Domain: "onlyverified.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)
	require.NoError(t, s.MarkDomainVerified(context.Background(), "onlyverified.example.net", time.Now()))

	_, err = h.ActivateOrganization(adminCtx(uuid.NewString()), &identityv1.ActivateOrganizationRequest{Domain: "onlyverified.example.net"})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestActivate_OnlyTestPassedRejected: a passed IdP test alone is not
// enough — an unverified domain must still block activation.
func TestActivate_OnlyTestPassedRejected(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "OnlyTested", Domain: "onlytested.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)

	d, gerr := s.GetSSODomain(context.Background(), "onlytested.example.net")
	require.NoError(t, gerr)
	require.NotNil(t, d.ConnectionID)

	_, err = h.RecordIdPTestResult(adminCtx(uuid.NewString()), &identityv1.RecordIdPTestResultRequest{
		ConnectionId: d.ConnectionID.String(), Success: true,
	})
	require.NoError(t, err)

	_, err = h.ActivateOrganization(adminCtx(uuid.NewString()), &identityv1.ActivateOrganizationRequest{Domain: "onlytested.example.net"})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// TestRecordIdPTestResult_FailureDoesNotMarkPassed: a recorded test failure
// must NOT flip test_passed_at, and must not itself be a gRPC error — a
// failed test is a valid recorded outcome, not an RPC failure.
func TestRecordIdPTestResult_FailureDoesNotMarkPassed(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "FailTest", Domain: "failtest.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)

	d, gerr := s.GetSSODomain(context.Background(), "failtest.example.net")
	require.NoError(t, gerr)
	require.NotNil(t, d.ConnectionID)

	_, err = h.RecordIdPTestResult(adminCtx(uuid.NewString()), &identityv1.RecordIdPTestResultRequest{
		ConnectionId: d.ConnectionID.String(), Success: false, Detail: "connection refused",
	})
	require.NoError(t, err, "a recorded test failure must not itself be a gRPC error")

	conn, cerr := s.GetIdPConnection(context.Background(), *d.ConnectionID)
	require.NoError(t, cerr)
	require.Nil(t, conn.TestPassedAt, "a failed test must not set test_passed_at")
}

// TestDisableOrganization_FlipsEnabledFalse: disabling an active connection
// flips enabled back to false, immediately removing it from routing.
func TestDisableOrganization_FlipsEnabledFalse(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName: "Disable", Domain: "disable.example.net", Protocol: "oidc",
	})
	require.NoError(t, err)

	d, gerr := s.GetSSODomain(context.Background(), "disable.example.net")
	require.NoError(t, gerr)
	require.NotNil(t, d.ConnectionID)
	connID := d.ConnectionID.String()

	require.NoError(t, s.MarkDomainVerified(context.Background(), "disable.example.net", time.Now()))
	_, err = h.RecordIdPTestResult(adminCtx(uuid.NewString()), &identityv1.RecordIdPTestResultRequest{
		ConnectionId: connID, Success: true,
	})
	require.NoError(t, err)

	activateResp, err := h.ActivateOrganization(adminCtx(uuid.NewString()), &identityv1.ActivateOrganizationRequest{Domain: "disable.example.net"})
	require.NoError(t, err)
	require.True(t, activateResp.GetOrganization().GetEnabled())

	disableResp, err := h.DisableOrganization(adminCtx(uuid.NewString()), &identityv1.DisableOrganizationRequest{Domain: "disable.example.net"})
	require.NoError(t, err)
	require.False(t, disableResp.GetOrganization().GetEnabled())

	conn, cerr := s.GetIdPConnection(context.Background(), *d.ConnectionID)
	require.NoError(t, cerr)
	require.False(t, conn.Enabled, "DisableOrganization must flip enabled back to false")
}

// TestActivateOrganization_RequiresAuth: unauthenticated callers are
// rejected before any DB work.
func TestActivateOrganization_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.ActivateOrganization(noopCtx(), &identityv1.ActivateOrganizationRequest{Domain: "ds.example.net"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// TestDisableOrganization_RequiresAuth: unauthenticated callers are rejected
// before any DB work.
func TestDisableOrganization_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.DisableOrganization(noopCtx(), &identityv1.DisableOrganizationRequest{Domain: "ds.example.net"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// TestRecordIdPTestResult_RequiresAuth: unauthenticated callers are rejected
// before any DB work.
func TestRecordIdPTestResult_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.RecordIdPTestResult(noopCtx(), &identityv1.RecordIdPTestResultRequest{ConnectionId: uuid.NewString(), Success: true})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}
