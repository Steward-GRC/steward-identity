// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// TestResolveLoginEmail covers turning a username into the sign-in email: an
// enabled, live, local account answers its email, matched case-insensitively
// and ignoring surrounding spaces. Every other input answers the same empty
// response with OK, byte for byte, so the answer never tells which usernames
// exist.
func TestResolveLoginEmail(t *testing.T) {
	h, s := newReadHandlerWithStore(t)
	ctx := context.Background()

	root, err := s.PreCreateLocalUserRoot(ctx, "Admin", "admin@example.org", "Admin")
	require.NoError(t, err)
	require.True(t, root.IsRoot)

	off, err := s.PreCreateLocalUser(ctx, "offuser", "off@example.org", "Off")
	require.NoError(t, err)
	_, err = s.SetEnabled(ctx, off.ID, false, nil, "test")
	require.NoError(t, err)

	dead, err := s.PreCreateLocalUser(ctx, "deaduser", "dead@example.org", "Dead")
	require.NoError(t, err)
	_, err = s.DeleteUser(ctx, dead.ID, nil, "test")
	require.NoError(t, err)

	sso, _, err := s.JITProvisionByEmail(ctx, "sso@example.org", "Sam", "Sso")
	require.NoError(t, err)
	_, err = s.UpdateUsername(ctx, sso.ID, "ssouser")
	require.NoError(t, err)
	got, err := s.GetUserByUsername(ctx, "ssouser")
	require.NoError(t, err)
	require.False(t, got.LocalAccount, "the fixture must be a federated account")

	resolve := func(username string) *identityv1.ResolveLoginEmailResponse {
		t.Helper()
		resp, err := h.ResolveLoginEmail(ctx, &identityv1.ResolveLoginEmailRequest{Username: username})
		require.NoError(t, err, "%q must answer OK, never an error", username)
		require.NotNil(t, resp)
		return resp
	}

	require.Equal(t, "admin@example.org", resolve("Admin").GetEmail())
	require.Equal(t, "admin@example.org", resolve("admin").GetEmail(), "case-insensitive")
	require.Equal(t, "admin@example.org", resolve("ADMIN").GetEmail(), "case-insensitive")
	require.Equal(t, "admin@example.org", resolve("  admin \t").GetEmail(), "surrounding spaces are trimmed")

	empty, err := proto.Marshal(&identityv1.ResolveLoginEmailResponse{})
	require.NoError(t, err)
	for name, username := range map[string]string{
		"unknown":       "nobody",
		"disabled":      "offuser",
		"deleted":       "deaduser",
		"sso":           "ssouser",
		"empty":         "",
		"only spaces":   "   ",
		"email-shaped":  "admin@example.org",
		"at in the end": "admin@",
	} {
		resp := resolve(username)
		require.Empty(t, resp.GetEmail(), name)
		b, err := proto.Marshal(resp)
		require.NoError(t, err)
		require.Equal(t, empty, b, "%s answers the same bytes as an unknown username", name)
	}
}
