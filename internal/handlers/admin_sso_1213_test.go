// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// verifyDomainNow starts + verifies a seeded domain via a matching TXT lookup,
// leaving it in the verified state so the rotate/recheck cases can assert the
// revoke transition. Returns the current token.
func verifyDomainNow(t *testing.T, h *handlers.SSOAdminHandler, s *store.Store, domain string) string {
	t.Helper()
	start, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: domain})
	require.NoError(t, err)
	token := start.GetToken()
	h.SetTXTLookup(func(_ context.Context, _ string) ([]string, error) {
		return []string{"steward-verify=" + token}, nil
	})
	res, err := h.VerifyDomain(adminCtx(uuid.NewString()), &identityv1.VerifyDomainRequest{Domain: domain})
	require.NoError(t, err)
	require.True(t, res.GetVerified())
	d, err := s.GetSSODomain(context.Background(), domain)
	require.NoError(t, err)
	require.True(t, d.Verified)
	return token
}

// TestStartDomainVerification_RotateMintsFreshTokenAndRevokes: rotate=true is
// the ONE explicit action that changes the token — it mints a fresh value,
// revokes the prior verified proof, and a subsequent non-rotate Start reuses
// the NEW token (stability resumes around the rotated value).
func TestStartDomainVerification_RotateMintsFreshTokenAndRevokes(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "rotate.example.net", "rotate-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())

	token1 := verifyDomainNow(t, h, s, "rotate.example.net")

	rot, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "rotate.example.net", Rotate: true})
	require.NoError(t, err)
	require.NotEmpty(t, rot.GetToken())
	require.NotEqual(t, token1, rot.GetToken(), "rotate must mint a fresh token")

	d, err := s.GetSSODomain(context.Background(), "rotate.example.net")
	require.NoError(t, err)
	require.False(t, d.Verified, "rotate must revoke the prior verified proof")

	again, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "rotate.example.net"})
	require.NoError(t, err)
	require.Equal(t, rot.GetToken(), again.GetToken(),
		"a non-rotate Start after a rotate must reuse the rotated token, not mint again")
}

// TestRecheckVerifiedDomains_RevokesDrifted: a verified domain whose TXT record
// has disappeared (definitive no-match) is flipped back to unverified by the
// periodic re-check.
func TestRecheckVerifiedDomains_RevokesDrifted(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "drift.example.net", "drift-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	verifyDomainNow(t, h, s, "drift.example.net")

	// Record removed: lookup succeeds but returns no matching record.
	h.SetTXTLookup(func(_ context.Context, _ string) ([]string, error) {
		return []string{"some-other-unrelated-txt"}, nil
	})
	checked, revoked, err := h.RecheckVerifiedDomains(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, checked)
	require.Equal(t, 1, revoked)

	d, err := s.GetSSODomain(context.Background(), "drift.example.net")
	require.NoError(t, err)
	require.False(t, d.Verified, "recheck must flip a drifted domain back to needs-reverification")
}

// TestRecheckVerifiedDomains_KeepsStillResolving: a verified domain whose TXT
// record still matches is left verified (revoked=0).
func TestRecheckVerifiedDomains_KeepsStillResolving(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "steady.example.net", "steady-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	verifyDomainNow(t, h, s, "steady.example.net") // leaves the matching lookup wired

	checked, revoked, err := h.RecheckVerifiedDomains(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, checked)
	require.Equal(t, 0, revoked)

	d, err := s.GetSSODomain(context.Background(), "steady.example.net")
	require.NoError(t, err)
	require.True(t, d.Verified)
}

// TestRecheckVerifiedDomains_TransientErrorDoesNotRevoke: a resolver error
// (NXDOMAIN, timeout, propagation) is skipped — the re-check never revokes on a
// lookup failure, only on a definitive no-match.
func TestRecheckVerifiedDomains_TransientErrorDoesNotRevoke(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "transient.example.net", "transient-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	verifyDomainNow(t, h, s, "transient.example.net")

	h.SetTXTLookup(func(_ context.Context, _ string) ([]string, error) {
		return nil, errors.New("lookup transient.example.net: no such host")
	})
	checked, revoked, err := h.RecheckVerifiedDomains(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, checked)
	require.Equal(t, 0, revoked, "a transient lookup error must not revoke")

	d, err := s.GetSSODomain(context.Background(), "transient.example.net")
	require.NoError(t, err)
	require.True(t, d.Verified, "verified must survive a transient DNS failure")
}

// TestChangeOrgProtocol_ResetsToStart: switching protocol on a fully-active org
// (verified + test-passed + enabled) re-provisions the backend IdP and resets
// BOTH gates + disables the connection, so the org is back at the start and the
// new protocol is persisted.
func TestChangeOrgProtocol_ResetsToStart(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "switch.example.net", "switch-verify") // seeded as oidc
	ctx := context.Background()
	d, err := s.GetSSODomain(ctx, "switch.example.net")
	require.NoError(t, err)
	connID := *d.ConnectionID

	// Bring it to a fully-active state.
	require.NoError(t, s.MarkDomainVerified(ctx, "switch.example.net", time.Now()))
	require.NoError(t, s.MarkIdPTestPassed(ctx, connID, time.Now()))
	require.NoError(t, s.SetIdPConnectionEnabled(ctx, connID, true))

	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	resp, err := h.ChangeOrgProtocol(adminCtx(uuid.NewString()), &identityv1.ChangeOrgProtocolRequest{
		Domain:   "switch.example.net",
		Protocol: "saml",
		Config: map[string]string{
			"entityId":               "https://switch.example.net/saml",
			"singleSignOnServiceUrl": "https://switch.example.net/saml/sso",
			"signingCertificate":     "AAAAbase64",
		},
	})
	require.NoError(t, err)

	org := resp.GetOrganization()
	require.Equal(t, "saml", org.GetProtocol())
	require.False(t, org.GetVerified(), "protocol change must reset the verified gate")
	require.False(t, org.GetTestPassed(), "protocol change must reset the test-passed gate")
	require.False(t, org.GetEnabled(), "protocol change must disable the connection")

	conn, err := s.GetIdPConnection(ctx, connID)
	require.NoError(t, err)
	require.Equal(t, "saml", conn.Protocol)
	require.Nil(t, conn.TestPassedAt)
	require.False(t, conn.Enabled)
	require.Equal(t, "https://switch.example.net/saml", conn.Config["entityId"])

	d, err = s.GetSSODomain(ctx, "switch.example.net")
	require.NoError(t, err)
	require.False(t, d.Verified)
}

// TestChangeOrgProtocol_SameProtocolRejected: a no-op protocol change is
// rejected rather than needlessly tearing the connection down.
func TestChangeOrgProtocol_SameProtocolRejected(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "noop.example.net", "noop-verify") // oidc
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.ChangeOrgProtocol(adminCtx(uuid.NewString()), &identityv1.ChangeOrgProtocolRequest{
		Domain: "noop.example.net", Protocol: "oidc",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for a same-protocol change, got %v", err)
	}
}

// TestChangeOrgProtocol_RequiresAuth: unauthenticated callers are rejected
// before any DB or backend work.
func TestChangeOrgProtocol_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.ChangeOrgProtocol(noopCtx(), &identityv1.ChangeOrgProtocolRequest{
		Domain: "switch.example.net", Protocol: "saml",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// TestChangeOrgProtocol_InvalidProtocol: only oidc|saml are accepted.
func TestChangeOrgProtocol_InvalidProtocol(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "bad.example.net", "bad-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.ChangeOrgProtocol(adminCtx(uuid.NewString()), &identityv1.ChangeOrgProtocolRequest{
		Domain: "bad.example.net", Protocol: "ldap",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}
