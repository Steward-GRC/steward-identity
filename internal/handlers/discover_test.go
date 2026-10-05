// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

func TestDiscover_ProtoSymbolsExist(t *testing.T) {
	_ = &identityv1.DiscoverRequest{Identifier: "x"}
	_ = &identityv1.DiscoverResponse{Method: "local"}
	_ = &identityv1.CheckBreakGlassEligibilityRequest{Email: "x@y.z"}
	_ = &identityv1.CheckBreakGlassEligibilityResponse{Eligible: true}
}

// newReadHandlerWithStore returns a ReadHandler and its backing store wired
// to a freshly-migrated test database. Skips the test (via newTestStore's
// t.Skip) when DATABASE_TEST_DSN is unset, matching every other handler
// integration test in this package.
func newReadHandlerWithStore(t *testing.T) (hintedRead, *store.Store) {
	t.Helper()
	s := newTestStore(t)
	return hinted(handlers.NewReadHandler(s)), s
}

// TestDiscover_EmailAndUsername covers identifier-first home-realm
// discovery: an "@"-identifier resolves by its domain directly; a bare
// username is treated as an email local-part and resolved to its user's
// email domain before the domain lookup; an unknown domain falls through to
// "local" so we never leak whether a domain is configured.
func TestDiscover_EmailAndUsername(t *testing.T) {
	h, s := newReadHandlerWithStore(t)
	ctx := context.Background()
	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	_, err = s.UpsertSSODomain(ctx, store.SSODomain{Domain: "example.org", Method: "sso", ConnectionID: &conn.ID})
	require.NoError(t, err)
	require.NoError(t, s.MarkDomainVerified(ctx, "example.org", time.Now()))
	require.NoError(t, s.MarkIdPTestPassed(ctx, conn.ID, time.Now()))
	require.NoError(t, s.SetIdPConnectionEnabled(ctx, conn.ID, true))
	// username = local part of a local user's email
	_, err = s.PreCreateLocalUser(ctx, "jane", "jane@example.org", "Jane")
	require.NoError(t, err)

	byEmail, err := h.Discover(ctx, &identityv1.DiscoverRequest{Identifier: "bob@example.org"})
	require.NoError(t, err)
	require.Equal(t, "sso", byEmail.Method)
	require.Equal(t, "example-org", byEmail.ConnectionAlias)

	byUser, err := h.Discover(ctx, &identityv1.DiscoverRequest{Identifier: "jane"})
	require.NoError(t, err)
	require.Equal(t, "sso", byUser.Method)

	unknown, err := h.Discover(ctx, &identityv1.DiscoverRequest{Identifier: "someone@nowhere.example.org"})
	require.NoError(t, err)
	require.Equal(t, "local", unknown.Method, "unknown domain falls through to a generic method, no leak")
}

// TestDiscover_AllowLocalFallback: an active sso domain whose
// connection opted into allow_local still routes method=sso but reports
// allow_local=true so the login gate can offer the local password form as a
// fallback. A default (allow_local=false) sso domain reports it false.
func TestDiscover_AllowLocalFallback(t *testing.T) {
	h, s := newReadHandlerWithStore(t)
	ctx := context.Background()
	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	_, err = s.UpsertSSODomain(ctx, store.SSODomain{Domain: "example.org", Method: "sso", ConnectionID: &conn.ID})
	require.NoError(t, err)
	require.NoError(t, s.MarkDomainVerified(ctx, "example.org", time.Now()))
	require.NoError(t, s.MarkIdPTestPassed(ctx, conn.ID, time.Now()))
	require.NoError(t, s.SetIdPConnectionEnabled(ctx, conn.ID, true))

	// Default: SSO-only, no local fallback.
	def, err := h.Discover(ctx, &identityv1.DiscoverRequest{Identifier: "bob@example.org"})
	require.NoError(t, err)
	require.Equal(t, "sso", def.Method)
	require.False(t, def.GetAllowLocal(), "default sso org is SSO-only")

	// Opt in to local fallback.
	allow := true
	require.NoError(t, s.SetIdPConnectionLoginToggles(ctx, conn.ID, nil, &allow))
	withLocal, err := h.Discover(ctx, &identityv1.DiscoverRequest{Identifier: "bob@example.org"})
	require.NoError(t, err)
	require.Equal(t, "sso", withLocal.Method, "sso is still the primary method")
	require.True(t, withLocal.GetAllowLocal(), "allow_local opt-in must surface in Discover")
}

// TestCheckBreakGlassEligibility_RootAndNotPrivileged drives the handler
// through real store state rather than asserting a tautology: a local root
// account must come back eligible, and a plain local user with no privileged
// role must come back not eligible with the "not_privileged" reason.
func TestCheckBreakGlassEligibility_RootAndNotPrivileged(t *testing.T) {
	h, s := newReadHandlerWithStore(t)
	ctx := context.Background()

	_, err := s.PreCreateLocalUserRoot(ctx, "root", "root@corp.example.net", "Root")
	require.NoError(t, err)
	resp, err := h.CheckBreakGlassEligibility(ctx, &identityv1.CheckBreakGlassEligibilityRequest{Email: "root@corp.example.net"})
	require.NoError(t, err)
	require.True(t, resp.GetEligible())
	require.Equal(t, "ok", resp.GetReason())

	_, err = s.PreCreateLocalUser(ctx, "bob", "bob@corp.example.net", "Bob")
	require.NoError(t, err)
	resp, err = h.CheckBreakGlassEligibility(ctx, &identityv1.CheckBreakGlassEligibilityRequest{Email: "bob@corp.example.net"})
	require.NoError(t, err)
	require.False(t, resp.GetEligible())
	require.Equal(t, "not_privileged", resp.GetReason())
}
