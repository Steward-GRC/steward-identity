// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestDiscoverMethod_SSOActiveOnlyWhenBothGates covers the two-gate rule: a
// domain configured for sso must not route users to the IdP until BOTH the
// domain is verified AND the connection is enabled with a passed test login.
func TestDiscoverMethod_SSOActiveOnlyWhenBothGates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{
		OrgName: "Partner Organisation", Protocol: "oidc", ConnectionAlias: "partner", DisplayName: "Partner Organisation",
	})
	require.NoError(t, err)
	_, err = s.UpsertSSODomain(ctx, store.SSODomain{Domain: "partner.example.net", Method: "sso", ConnectionID: &conn.ID})
	require.NoError(t, err)

	got, err := s.DiscoverMethod(ctx, "partner.example.net")
	require.NoError(t, err)
	require.Equal(t, "local", got.Method, "unverified+untested domain must not route to sso")

	// pass both gates
	require.NoError(t, s.MarkDomainVerified(ctx, "partner.example.net", time.Now()))
	require.NoError(t, s.MarkIdPTestPassed(ctx, conn.ID, time.Now()))
	require.NoError(t, s.SetIdPConnectionEnabled(ctx, conn.ID, true))

	got, err = s.DiscoverMethod(ctx, "partner.example.net")
	require.NoError(t, err)
	require.Equal(t, "sso", got.Method)
	require.Equal(t, "partner", got.ConnectionAlias)
	require.Empty(t, got.IdPInitiatedSSOURL, "a connection without an idpInitiatedSsoUrl config key yields an empty launch URL")
}

// TestHasActiveSSO covers the global "is any SSO usable" gate the login UI
// reads to enable/disable the "Sign in with SSO" button: false until some
// method=sso domain is verified AND its connection enabled AND test-passed.
func TestHasActiveSSO(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Nothing configured at all → false.
	has, err := s.HasActiveSSO(ctx)
	require.NoError(t, err)
	require.False(t, has, "no domains configured → no active sso")

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{
		OrgName: "Partner Organisation", Protocol: "oidc", ConnectionAlias: "partner", DisplayName: "Partner Organisation",
	})
	require.NoError(t, err)
	_, err = s.UpsertSSODomain(ctx, store.SSODomain{Domain: "partner.example.net", Method: "sso", ConnectionID: &conn.ID})
	require.NoError(t, err)

	// Configured but half-armed (unverified, disabled, no passed test) → false,
	// exactly matching DiscoverMethod's fall-back-to-local gate.
	has, err = s.HasActiveSSO(ctx)
	require.NoError(t, err)
	require.False(t, has, "a half-configured sso domain must not count as active")

	// Verified only — still gated on the connection.
	require.NoError(t, s.MarkDomainVerified(ctx, "partner.example.net", time.Now()))
	has, err = s.HasActiveSSO(ctx)
	require.NoError(t, err)
	require.False(t, has, "verified domain with a disabled/untested connection is not active")

	// Pass every gate → true.
	require.NoError(t, s.MarkIdPTestPassed(ctx, conn.ID, time.Now()))
	require.NoError(t, s.SetIdPConnectionEnabled(ctx, conn.ID, true))
	has, err = s.HasActiveSSO(ctx)
	require.NoError(t, err)
	require.True(t, has, "verified domain + enabled + test-passed connection → active sso")

	// Disabling the connection again drops it back to false.
	require.NoError(t, s.SetIdPConnectionEnabled(ctx, conn.ID, false))
	has, err = s.HasActiveSSO(ctx)
	require.NoError(t, err)
	require.False(t, has, "disabling the connection removes the only active sso")
}

// TestDiscoverMethod_IdPInitiatedURL covers Option A: an active method=sso
// connection whose config carries idpInitiatedSsoUrl surfaces that launch URL
// on the DiscoverResult so the gateway can start /login by redirecting to the
// IdP's unsolicited-assertion launch URL instead of an SP-initiated AuthnRequest.
func TestDiscoverMethod_IdPInitiatedURL(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const launch = "https://idp.example.net/saml/launch?app=ABC123&sp=456"
	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{
		OrgName: "Second Partner", Protocol: "saml", ConnectionAlias: "second-partner", DisplayName: "Second Partner",
		Config: map[string]any{"idpInitiatedSsoUrl": launch},
	})
	require.NoError(t, err)
	_, err = s.UpsertSSODomain(ctx, store.SSODomain{Domain: "second.example.net", Method: "sso", ConnectionID: &conn.ID})
	require.NoError(t, err)
	require.NoError(t, s.MarkDomainVerified(ctx, "second.example.net", time.Now()))
	require.NoError(t, s.MarkIdPTestPassed(ctx, conn.ID, time.Now()))
	require.NoError(t, s.SetIdPConnectionEnabled(ctx, conn.ID, true))

	got, err := s.DiscoverMethod(ctx, "second.example.net")
	require.NoError(t, err)
	require.Equal(t, "sso", got.Method)
	require.Equal(t, "second-partner", got.ConnectionAlias)
	require.Equal(t, launch, got.IdPInitiatedSSOURL)
}

// TestDiscoverMethod_NotFound covers the not-configured case.
func TestDiscoverMethod_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.DiscoverMethod(ctx, "unknown.example.org")
	require.ErrorIs(t, err, store.ErrNotFound)
}

// TestDiscoverMethod_Local covers the plain local method passing through
// DiscoverMethod unchanged, and the directory method being gone.
func TestDiscoverMethod_Local(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.UpsertSSODomain(ctx, store.SSODomain{Domain: "local.example.org", Method: "local"})
	require.NoError(t, err)
	_, err = s.UpsertSSODomain(ctx, store.SSODomain{Domain: "ad.example.org", Method: "ad"})
	require.Error(t, err, "only local and sso are sign-in methods")

	got, err := s.DiscoverMethod(ctx, "local.example.org")
	require.NoError(t, err)
	require.Equal(t, "local", got.Method)
	require.Empty(t, got.ConnectionAlias)
}

// TestSSODomainCRUD covers Upsert/Get/List/Delete round-tripping, including
// domain lowercasing and upsert-on-conflict semantics.
func TestSSODomainCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.UpsertSSODomain(ctx, store.SSODomain{Domain: "Example.ORG", Method: "local", CreatedBy: "tester"})
	require.NoError(t, err)
	require.Equal(t, "example.org", created.Domain, "domain must be lowercased")
	require.False(t, created.Verified)
	require.Nil(t, created.VerifiedAt)

	got, err := s.GetSSODomain(ctx, "EXAMPLE.org")
	require.NoError(t, err)
	require.Equal(t, created, got)

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{
		OrgName: "Example Organisation", Protocol: "saml", ConnectionAlias: "example-org", DisplayName: "Example Organisation",
	})
	require.NoError(t, err)

	updated, err := s.UpsertSSODomain(ctx, store.SSODomain{Domain: "example.org", Method: "sso", ConnectionID: &conn.ID})
	require.NoError(t, err)
	require.Equal(t, "sso", updated.Method)
	require.NotNil(t, updated.ConnectionID)
	require.Equal(t, conn.ID, *updated.ConnectionID)

	list, err := s.ListSSODomains(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "example.org", list[0].Domain)

	require.NoError(t, s.DeleteSSODomain(ctx, "example.org"))
	_, err = s.GetSSODomain(ctx, "example.org")
	require.ErrorIs(t, err, store.ErrNotFound)

	err = s.DeleteSSODomain(ctx, "example.org")
	require.ErrorIs(t, err, store.ErrNotFound)

	empty, err := s.ListSSODomains(ctx)
	require.NoError(t, err)
	require.NotNil(t, empty)
	require.Empty(t, empty)
}

// TestIdPConnectionGating covers SetIdPConnectionEnabled / MarkIdPTestPassed
// mutating the row and returning ErrNotFound for unknown ids.
func TestIdPConnectionGating(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{
		OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org-gate", DisplayName: "Example Organisation",
	})
	require.NoError(t, err)
	require.False(t, conn.Enabled)
	require.Nil(t, conn.TestPassedAt)

	require.NoError(t, s.SetIdPConnectionEnabled(ctx, conn.ID, true))
	require.NoError(t, s.MarkIdPTestPassed(ctx, conn.ID, time.Now()))

	unknown, err := s.GetSSODomain(ctx, "unrelated.example.org")
	require.ErrorIs(t, err, store.ErrNotFound)
	require.Zero(t, unknown)

	require.ErrorIs(t, s.SetIdPConnectionEnabled(ctx, uuid.New(), true), store.ErrNotFound)
	require.ErrorIs(t, s.MarkIdPTestPassed(ctx, uuid.New(), time.Now()), store.ErrNotFound)
	require.ErrorIs(t, s.MarkDomainVerified(ctx, "unrelated.example.org", time.Now()), store.ErrNotFound)
}
