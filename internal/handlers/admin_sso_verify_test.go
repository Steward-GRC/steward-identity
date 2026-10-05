// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// seedSSODomain registers a disabled sso connection + domain so
// StartDomainVerification's precondition (domain_verification.domain has an
// FK to sso_domains.domain) is satisfied — mirroring what AddOrganization
// does in production before activation begins.
func seedSSODomain(t *testing.T, s *store.Store, domain, alias string) {
	t.Helper()
	conn, err := s.CreateIdPConnection(context.Background(), store.IdPConnection{
		OrgName: "Partner Organisation", Protocol: "oidc", ConnectionAlias: alias, DisplayName: "Partner Organisation",
	})
	require.NoError(t, err)
	_, err = s.UpsertSSODomain(context.Background(), store.SSODomain{
		Domain: domain, Method: "sso", ConnectionID: &conn.ID,
	})
	require.NoError(t, err)
}

// TestVerifyDomain_MatchesTXT is the load-bearing case: a TXT record
// matching the token minted by StartDomainVerification verifies the domain
// and flips the sso_domains gate.
func TestVerifyDomain_MatchesTXT(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "partner.example.net", "partner-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())

	start, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	require.NotEmpty(t, start.GetToken())
	require.Equal(t, "_steward-verify.partner.com", start.GetDnsRecordName())
	require.NotEmpty(t, start.GetInstructions())
	token := start.GetToken()

	h.SetTXTLookup(func(_ context.Context, name string) ([]string, error) {
		require.Equal(t, "_steward-verify.partner.com", name)
		return []string{"steward-verify=" + token}, nil
	})
	res, err := h.VerifyDomain(adminCtx(uuid.NewString()), &identityv1.VerifyDomainRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	require.True(t, res.GetVerified())

	d, gerr := s.GetSSODomain(context.Background(), "partner.example.net")
	require.NoError(t, gerr)
	require.True(t, d.Verified, "a matching TXT record must flip the sso_domains verified gate")
}

// TestStartDomainVerification_TokenStable: re-calling Start for a domain that
// already has a pending verification returns the SAME token, so a TXT record the
// admin already published is never silently invalidated by a restart.
func TestStartDomainVerification_TokenStable(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "stable.example.net", "stable-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())

	first, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "stable.example.net"})
	require.NoError(t, err)
	require.NotEmpty(t, first.GetToken())

	second, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "stable.example.net"})
	require.NoError(t, err)
	require.Equal(t, first.GetToken(), second.GetToken(),
		"re-Start must reuse the pending token, not rotate it")
}

// TestVerifyDomain_NonMatchingTXT: a TXT record is present but doesn't equal
// the minted token — verified must be false, and this must NOT be a gRPC
// error (an admin can legitimately retry after fixing the record).
func TestVerifyDomain_NonMatchingTXT(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "wrongtoken.example.net", "wrongtoken-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())

	_, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "wrongtoken.example.net"})
	require.NoError(t, err)

	h.SetTXTLookup(func(_ context.Context, _ string) ([]string, error) {
		return []string{"steward-verify=not-the-real-token"}, nil
	})
	res, err := h.VerifyDomain(adminCtx(uuid.NewString()), &identityv1.VerifyDomainRequest{Domain: "wrongtoken.example.net"})
	require.NoError(t, err)
	require.False(t, res.GetVerified())

	d, gerr := s.GetSSODomain(context.Background(), "wrongtoken.example.net")
	require.NoError(t, gerr)
	require.False(t, d.Verified)
}

// TestVerifyDomain_LookupErrorReturnsUnverifiedNotError: a resolver error
// (NXDOMAIN, transient failure, DNS propagation delay) must not fail the
// RPC — it is logged and reported as verified=false, exactly like a
// non-match, since it's an ordinary pollable state for an admin waiting on
// DNS propagation.
func TestVerifyDomain_LookupErrorReturnsUnverifiedNotError(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "dnserr.example.net", "dnserr-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())

	_, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "dnserr.example.net"})
	require.NoError(t, err)

	h.SetTXTLookup(func(_ context.Context, _ string) ([]string, error) {
		return nil, errors.New("lookup dnserr.example.net: no such host")
	})
	res, err := h.VerifyDomain(adminCtx(uuid.NewString()), &identityv1.VerifyDomainRequest{Domain: "dnserr.example.net"})
	require.NoError(t, err)
	require.False(t, res.GetVerified())
}

// TestStartDomainVerification_RequiresAuth: unauthenticated callers are
// rejected before any DB work.
func TestStartDomainVerification_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.StartDomainVerification(noopCtx(), &identityv1.StartDomainVerificationRequest{Domain: "partner.example.net"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// TestVerifyDomain_RequiresAuth: unauthenticated callers are rejected before
// any DB or DNS work.
func TestVerifyDomain_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.VerifyDomain(noopCtx(), &identityv1.VerifyDomainRequest{Domain: "partner.example.net"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// TestStartDomainVerification_UnknownDomainNotFound: a domain never
// registered via AddOrganization must not be verifiable — StartDomainVerification
// requires the sso_domains row to already exist.
func TestStartDomainVerification_UnknownDomainNotFound(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "never-added.example.com"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

// TestStartDomainVerification_DnsRecordValueDefaultPrefix: the response carries
// the exact TXT value to publish, built from the (default) prefix and token —
// prod's clean "steward-verify=<token>".
func TestStartDomainVerification_DnsRecordValueDefaultPrefix(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "valuecase.example.net", "valuecase-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())

	start, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "valuecase.example.net"})
	require.NoError(t, err)
	require.Equal(t, "steward-verify="+start.GetToken(), start.GetDnsRecordValue())
}

// TestStartDomainVerification_DnsRecordValuePerEnvPrefix: a per-environment
// prefix flows into BOTH the record name and the record value, and the same
// prefix is what VerifyDomain looks up + matches — so a dev record
// (steward-verify-dev=<token>) verifies under the dev prefix end-to-end.
func TestStartDomainVerification_DnsRecordValuePerEnvPrefix(t *testing.T) {
	s := newTestStore(t)
	seedSSODomain(t, s, "perenv.example.net", "perenv-verify")
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).
		WithVerifyTXTPrefix("steward-verify-dev")

	start, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "perenv.example.net"})
	require.NoError(t, err)
	require.Equal(t, "_steward-verify-dev.perenv.com", start.GetDnsRecordName())
	require.Equal(t, "steward-verify-dev="+start.GetToken(), start.GetDnsRecordValue())

	h.SetTXTLookup(func(_ context.Context, name string) ([]string, error) {
		require.Equal(t, "_steward-verify-dev.perenv.com", name)
		return []string{start.GetDnsRecordValue()}, nil
	})
	res, err := h.VerifyDomain(adminCtx(uuid.NewString()), &identityv1.VerifyDomainRequest{Domain: "perenv.example.net"})
	require.NoError(t, err)
	require.True(t, res.GetVerified())
}
