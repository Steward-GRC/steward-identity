// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBreakGlassLoginEligible covers the eligibility branches: a local root
// account resolved by BOTH email and username (eligible), a federated
// site-admin with no local credential (not eligible — federated-only), and a
// plain local user with no privileged role (not eligible — not privileged).
func TestBreakGlassLoginEligible(t *testing.T) {
	s := newTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()

	root, err := s.PreCreateLocalUserRoot(ctx, "root", "root@corp.example.org", "Root")
	require.NoError(t, err)
	ok, reason, err := s.BreakGlassLoginEligible(ctx, "root@corp.example.org")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "ok", reason)
	_ = root

	// SAME root resolved by USERNAME (not email) -> eligible. Matching by email
	// only previously returned "unknown_user" here, which blocked a root/site-admin
	// who typed their username at the break-glass form.
	ok, reason, err = s.BreakGlassLoginEligible(ctx, "root")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "ok", reason)

	// identifier match is case-insensitive on the username too.
	ok, reason, err = s.BreakGlassLoginEligible(ctx, "ROOT")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "ok", reason)

	// site-admin but NO local credential (federated-only) -> not eligible
	fed, err := s.JITProvision(ctx, "kc-sub-1", "adm@corp.example.org", "Adm")
	require.NoError(t, err)
	_, err = s.GrantRole(ctx, fed.ID, "site-admin", "", nil, "test")
	require.NoError(t, err)
	ok, reason, err = s.BreakGlassLoginEligible(ctx, "adm@corp.example.org")
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "no_local_credential", reason)

	// plain local user, not privileged -> not eligible
	_, err = s.PreCreateLocalUser(ctx, "bob", "bob@corp.example.org", "Bob")
	require.NoError(t, err)
	ok, reason, err = s.BreakGlassLoginEligible(ctx, "bob@corp.example.org")
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "not_privileged", reason)

	// unknown email -> unknown_user
	ok, reason, err = s.BreakGlassLoginEligible(ctx, "nobody@corp.example.org")
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "unknown_user", reason)
}
