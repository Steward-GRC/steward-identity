// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestJITProvisionByEmail_CreatesFederatedUser proves a first-seen email is
// provisioned as a FEDERATED row: empty external_subject, local_account=false,
// NOT is_root, enabled, with email/first/last/derived-username set and the
// display name composed from the parts.
func TestJITProvisionByEmail_CreatesFederatedUser(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, created, err := s.JITProvisionByEmail(ctx, "alice@example.org", "Alice", "Archer")
	require.NoError(t, err)
	require.True(t, created, "a first-seen email must be freshly created")

	require.NotEqual(t, uuid.Nil, u.ID)
	require.Equal(t, "alice@example.org", u.Email)
	require.Equal(t, "Alice", u.FirstName)
	require.Equal(t, "Archer", u.LastName)
	require.Equal(t, "Alice Archer", u.Name, "display name is derived from the parts")
	require.Equal(t, "alice", u.Username, "username derived from the email local-part")
	require.Empty(t, u.ExternalSubject, "federated Polis users have no external subject")
	require.False(t, u.LocalAccount, "SSO users are federated, not local_account")
	require.False(t, u.IsRoot)
	require.True(t, u.Enabled)
	require.Empty(t, u.Roles, "reader is implicit; no stored roles on JIT")

	// user.created + user.login.success emitted in-transaction.
	n, err := s.CountAuditPending(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
}

// TestJITProvisionByEmail_EmptyNamesTolerated: an IdP that asserted no name
// still provisions; the display name is left empty for onboarding to fill.
func TestJITProvisionByEmail_EmptyNamesTolerated(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u, created, err := s.JITProvisionByEmail(ctx, "noname@example.org", "", "")
	require.NoError(t, err)
	require.True(t, created)
	require.Empty(t, u.Name)
	require.Empty(t, u.FirstName)
	require.Empty(t, u.LastName)
	require.Equal(t, "noname", u.Username)
}

// TestJITProvisionByEmail_ExistingReturnsNoDup: a second call for the same
// email returns the SAME row (created=false) and never inserts a duplicate.
// Case-insensitive: a different-cased email resolves to the same row.
func TestJITProvisionByEmail_ExistingReturnsNoDup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first, created, err := s.JITProvisionByEmail(ctx, "dup@example.org", "First", "Last")
	require.NoError(t, err)
	require.True(t, created)

	second, created2, err := s.JITProvisionByEmail(ctx, "DUP@EXAMPLE.ORG", "Ignored", "Ignored")
	require.NoError(t, err)
	require.False(t, created2, "an existing email is a no-op, never a re-create")
	require.Equal(t, first.ID, second.ID)
	// The idempotent hit returns the existing row unchanged (names not overwritten).
	require.Equal(t, "First", second.FirstName)
}

// TestJITProvisionByEmail_AdoptsExistingLocalUser: a pre-existing user (here a
// subject-keyed row, but equally a local account) that already carries the
// email is returned as-is — JIT never shadows an existing platform identity.
func TestJITProvisionByEmail_AdoptsExistingLocalUser(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	existing, err := s.JITProvision(ctx, "kc-sub-1", "already@example.org", "Already Here")
	require.NoError(t, err)

	u, created, err := s.JITProvisionByEmail(ctx, "already@example.org", "Should", "Ignore")
	require.NoError(t, err)
	require.False(t, created, "an email already owned by a platform user is not re-created")
	require.Equal(t, existing.ID, u.ID)
	require.Equal(t, "kc-sub-1", u.ExternalSubject, "the existing (subject-keyed) row is returned untouched")
}

// TestJITProvisionByEmail_EmptyEmailRejected: an empty email is ErrInvalid.
func TestJITProvisionByEmail_EmptyEmailRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, _, err := s.JITProvisionByEmail(ctx, "   ", "A", "B")
	require.Error(t, err)
	require.True(t, errors.Is(err, store.ErrInvalid))
}

// TestJITProvisionByEmail_ConcurrentIsIdempotent: N concurrent first-logins for
// the same email must create EXACTLY one row (advisory-lock serialized) and all
// resolve to the same id.
func TestJITProvisionByEmail_ConcurrentIsIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const n = 8
	var wg sync.WaitGroup
	ids := make([]uuid.UUID, n)
	createdFlags := make([]bool, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			u, created, err := s.JITProvisionByEmail(ctx, "race@example.org", "Race", "Test")
			ids[i], createdFlags[i], errs[i] = u.ID, created, err
		}(i)
	}
	wg.Wait()

	createdCount := 0
	for i := range n {
		require.NoError(t, errs[i])
		require.Equal(t, ids[0], ids[i], "every concurrent caller must resolve the same row")
		if createdFlags[i] {
			createdCount++
		}
	}
	require.Equal(t, 1, createdCount, "exactly one caller may report a fresh create")
}
