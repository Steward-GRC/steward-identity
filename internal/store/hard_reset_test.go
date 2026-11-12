// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// newRoot makes a root admin with site-admin by writing the rows directly:
// the store itself offers no way to add a second root.
func newRoot(t *testing.T, pool *pgxpool.Pool, s *store.Store, name string) store.User {
	t.Helper()
	ctx := context.Background()
	u, err := s.PreCreateLocalUser(ctx, name, name+"@roots.example.org", name)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE users SET is_root = true WHERE id = $1`, u.ID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '') ON CONFLICT DO NOTHING`, u.ID)
	require.NoError(t, err)
	g, err := s.GetUser(ctx, u.ID)
	require.NoError(t, err)
	return g
}

// newSeveralRootsStore returns a store on a database where the single-root
// index is dropped. The two-person hard reset still needs two root admins and
// is out of scope for the single-root change, so its tests keep running on a
// database that allows them.
func newSeveralRootsStore(t *testing.T) (*pgxpool.Pool, *store.Store) {
	t.Helper()
	pool := newTestDB(t)
	_, err := pool.Exec(context.Background(), `DROP INDEX users_single_root_idx`)
	require.NoError(t, err)
	return pool, newStoreFor(t, pool)
}

func auditTypes(t *testing.T, s *store.Store) []string {
	t.Helper()
	events, err := s.PendingAuditEvents(context.Background(), 1000)
	require.NoError(t, err)
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.EventType)
	}
	return out
}

func TestBootstrapRoot_RefusedOnceAnyRootExists(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.PreCreateLocalUserRoot(ctx, "first", "first@roots.example.org", "First")
	require.NoError(t, err)
	_, err = s.PreCreateLocalUserRoot(ctx, "second", "second@roots.example.org", "Second")
	require.ErrorIs(t, err, store.ErrConflict, "bootstrap makes only the first root")
}

func TestHardReset_TwoPersonFlow(t *testing.T) {
	pool, s := newSeveralRootsStore(t)
	ctx := context.Background()
	a := newRoot(t, pool, s, "roota")
	b := newRoot(t, pool, s, "rootb")
	now := time.Now().UTC().Truncate(time.Microsecond)

	r, err := s.CreateHardResetRequest(ctx, "compliance", "fresh start", a.ID, now, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, store.HardResetPending, r.State)
	require.Equal(t, a.ID, r.RequestedBy)
	require.WithinDuration(t, now.Add(24*time.Hour), r.ExpiresAt, time.Second)

	_, err = s.CreateHardResetRequest(ctx, "compliance", "again", b.ID, now, 24*time.Hour)
	require.ErrorIs(t, err, store.ErrConflict, "one open request per module")

	_, err = s.ApproveHardResetRequest(ctx, r.ID, a.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrSelfApproval)

	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "a pending request can't be used")

	r, err = s.ApproveHardResetRequest(ctx, r.ID, b.ID, now, time.Hour)
	require.NoError(t, err)
	require.Equal(t, store.HardResetApproved, r.State)
	require.Equal(t, b.ID, *r.ApprovedBy)
	require.WithinDuration(t, now.Add(time.Hour), *r.ApprovalExpiresAt, time.Second)

	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "ethics", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "the module must match")

	r, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.NoError(t, err)
	require.Equal(t, store.HardResetConsumed, r.State)
	require.Equal(t, "reporting", r.ConsumedBy)

	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "single use")

	types := auditTypes(t, s)
	for _, e := range []string{"hard_reset.requested", "hard_reset.approved", "hard_reset.consumed"} {
		require.Contains(t, types, e)
	}
}

func TestHardReset_ExpiryAndCancel(t *testing.T) {
	pool, s := newSeveralRootsStore(t)
	ctx := context.Background()
	a := newRoot(t, pool, s, "roota")
	b := newRoot(t, pool, s, "rootb")
	now := time.Now().UTC()

	r, err := s.CreateHardResetRequest(ctx, "compliance", "r1", a.ID, now, 24*time.Hour)
	require.NoError(t, err)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, b.ID, now.Add(25*time.Hour), time.Hour)
	require.ErrorIs(t, err, store.ErrHardResetState, "an unapproved request expires")

	list, err := s.ListHardResetRequests(ctx, "compliance", now.Add(25*time.Hour))
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, store.HardResetExpired, list[0].State)

	r, err = s.CreateHardResetRequest(ctx, "compliance", "r2", a.ID, now.Add(25*time.Hour), 24*time.Hour)
	require.NoError(t, err, "an expired request no longer blocks a new one")
	later := now.Add(25 * time.Hour)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, b.ID, later, time.Hour)
	require.NoError(t, err)
	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", later.Add(2*time.Hour))
	require.ErrorIs(t, err, store.ErrHardResetState, "an approval expires")

	r, err = s.CreateHardResetRequest(ctx, "compliance", "r3", a.ID, later.Add(2*time.Hour), 24*time.Hour)
	require.NoError(t, err)
	_, err = s.CancelHardResetRequest(ctx, r.ID, b.ID, later.Add(2*time.Hour))
	require.ErrorIs(t, err, store.ErrNotRequester, "only the requester cancels")
	r, err = s.CancelHardResetRequest(ctx, r.ID, a.ID, later.Add(2*time.Hour))
	require.NoError(t, err)
	require.Equal(t, store.HardResetCancelled, r.State)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, b.ID, later.Add(2*time.Hour), time.Hour)
	require.ErrorIs(t, err, store.ErrHardResetState)

	types := auditTypes(t, s)
	require.Contains(t, types, "hard_reset.expired")
	require.Contains(t, types, "hard_reset.cancelled")
}

func TestHardReset_OnlyRootsTakePart(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	a := newRoot(t, pool, s, "roota")
	plain, err := s.PreCreateLocalUser(ctx, "plain", "plain@roots.example.org", "Plain")
	require.NoError(t, err)
	now := time.Now().UTC()

	_, err = s.CreateHardResetRequest(ctx, "compliance", "x", plain.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrRootRequired)
	r, err := s.CreateHardResetRequest(ctx, "compliance", "x", a.ID, now, time.Hour)
	require.NoError(t, err)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, plain.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrRootRequired)
	_, err = s.ApproveHardResetRequest(ctx, uuid.New(), a.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrNotFound)
}
