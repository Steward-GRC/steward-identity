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
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestResolveClaims_AppliesGroupMappingButZeroAccessWhenNone is the core case: a
// JIT/adopt login carrying a gateway-forwarded IdP alias + asserted groups
// must land the user in whatever platform group the connection's mapping
// points at. Absent an alias, or absent asserted groups, the user must keep
// the plain "everyone"-only zero-access default — no group is added.
//
// The User proto's groups field carries platform group IDs (not names), so
// the "landed in the mapped group" assertion checks for the created group's
// ID string, matching the actual wire shape.
func TestResolveClaims_AppliesGroupMappingButZeroAccessWhenNone(t *testing.T) {
	h, s := newReadHandlerWithStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Engineering", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)
	_, err = s.AddIdPGroupMapping(ctx, conn.ID, "eng", g.ID)
	require.NoError(t, err)

	mappedCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email":      "bob@example.org",
		"x-identity-idp-alias":  "example-org",
		"x-identity-idp-groups": "eng",
	})
	resp, err := h.ResolveClaims(mappedCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-bob"})
	require.NoError(t, err)
	require.Contains(t, resp.GetUser().GetGroups(), g.ID.String(), "asserted group with a mapping lands the user in the target group")

	noGroupsCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email":     "no@example.org",
		"x-identity-idp-alias": "example-org",
	})
	resp2, err := h.ResolveClaims(noGroupsCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-no"})
	require.NoError(t, err)
	require.Empty(t, resp2.GetUser().GetGroups(), "no asserted groups -> zero access default")
}

// TestResolveClaims_UnknownIdPAliasNeverFailsLogin verifies the never-fail
// contract: an alias that doesn't resolve to a connection (typo, stale
// gateway config) must not block the login — the user still resolves with
// the zero-access default rather than an error.
func TestResolveClaims_UnknownIdPAliasNeverFailsLogin(t *testing.T) {
	h, _ := newReadHandlerWithStore(t)
	ctx := context.Background()

	badAliasCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email":      "ghost@example.org",
		"x-identity-idp-alias":  "does-not-exist",
		"x-identity-idp-groups": "eng",
	})
	resp, err := h.ResolveClaims(badAliasCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-ghost"})
	require.NoError(t, err, "unknown idp alias must never fail the login")
	require.Empty(t, resp.GetUser().GetGroups())
}

// TestResolveClaims_JitDisabledFailsClosedForNewUser: when the
// forwarded idp alias resolves to a connection with jit_enabled=false, a
// first-seen subject is NOT JIT-created — the login fails closed with a coded
// PermissionDenied and no user row is written. An already-known subject still
// resolves normally through the same connection.
func TestResolveClaims_JitDisabledFailsClosedForNewUser(t *testing.T) {
	h, s := newReadHandlerWithStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	jitOff := false
	require.NoError(t, s.SetIdPConnectionLoginToggles(ctx, conn.ID, &jitOff, nil))

	// First-seen subject: fail closed, no row created.
	newCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email":     "newbie@example.org",
		"x-identity-idp-alias": "example-org",
	})
	_, err = h.ResolveClaims(newCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-newbie"})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "jit-disabled new SSO user must fail closed")
	_, getErr := s.GetUserByEmail(ctx, "newbie@example.org")
	require.ErrorIs(t, getErr, store.ErrNotFound, "fail-closed must not create a row")

	// A subject already provisioned still resolves through the same connection.
	_, err = s.JITProvision(ctx, "sub-known", "known@example.org", "Known")
	require.NoError(t, err)
	knownCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email":     "known@example.org",
		"x-identity-idp-alias": "example-org",
	})
	resp, err := h.ResolveClaims(knownCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-known"})
	require.NoError(t, err, "an existing user must still log in with jit disabled")
	require.Equal(t, "known@example.org", resp.GetUser().GetEmail())
}
