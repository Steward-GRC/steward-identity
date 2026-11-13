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

// newSiteAdmin makes an ordinary account that holds the global site-admin
// right (not root).
func newSiteAdmin(t *testing.T, pool *pgxpool.Pool, s *store.Store, name string) store.User {
	t.Helper()
	ctx := context.Background()
	u, err := s.PreCreateLocalUser(ctx, name, name+"@admins.example.org", name)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '') ON CONFLICT DO NOTHING`, u.ID)
	require.NoError(t, err)
	return u
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

func TestHardReset_RootRequestsSiteAdminApprovesRedeemOnce(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root := newRoot(t, pool, s, "root")
	admin := newSiteAdmin(t, pool, s, "admin")
	now := time.Now().UTC().Truncate(time.Microsecond)

	r, err := s.CreateHardResetRequest(ctx, "compliance", "fresh start", root.ID, now, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, store.HardResetPending, r.State)
	require.Equal(t, root.ID, r.RequestedBy)
	require.WithinDuration(t, now.Add(24*time.Hour), r.ExpiresAt, time.Second)

	_, err = s.CreateHardResetRequest(ctx, "compliance", "again", root.ID, now, 24*time.Hour)
	require.ErrorIs(t, err, store.ErrConflict, "one open request per module")

	_, err = s.ApproveHardResetRequest(ctx, r.ID, root.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrSelfApproval, "root can't approve its own request")

	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "a pending request can't be used")

	r, err = s.ApproveHardResetRequest(ctx, r.ID, admin.ID, now, time.Hour)
	require.NoError(t, err)
	require.Equal(t, store.HardResetApproved, r.State)
	require.Equal(t, admin.ID, *r.ApprovedBy)
	require.WithinDuration(t, now.Add(time.Hour), *r.ApprovalExpiresAt, time.Second)

	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "ethics", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "the module must match")

	r, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.NoError(t, err)
	require.Equal(t, store.HardResetConsumed, r.State)
	require.Equal(t, "reporting", r.ConsumedBy)
	require.Equal(t, root.ID, r.RequestedBy)
	require.Equal(t, admin.ID, *r.ApprovedBy)

	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "single use")

	types := auditTypes(t, s)
	for _, e := range []string{"hard_reset.requested", "hard_reset.approved", "hard_reset.consumed"} {
		require.Contains(t, types, e)
	}
}

func TestHardReset_ApproverMustBeAnActiveSiteAdmin(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root := newRoot(t, pool, s, "root")
	admin := newSiteAdmin(t, pool, s, "admin")
	plain, err := s.PreCreateLocalUser(ctx, "plain", "plain@admins.example.org", "Plain")
	require.NoError(t, err)
	scoped, err := s.PreCreateLocalUser(ctx, "scoped", "scoped@admins.example.org", "Scoped")
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'author', 'hr')`, scoped.ID)
	require.NoError(t, err)
	disabled := newSiteAdmin(t, pool, s, "disabled")
	_, err = s.SetEnabled(ctx, disabled.ID, false, nil, "test")
	require.NoError(t, err)
	gone := newSiteAdmin(t, pool, s, "gone")
	_, err = pool.Exec(ctx, `UPDATE users SET deleted_at = now() WHERE id = $1`, gone.ID)
	require.NoError(t, err)
	now := time.Now().UTC()

	r, err := s.CreateHardResetRequest(ctx, "compliance", "x", root.ID, now, time.Hour)
	require.NoError(t, err)
	for name, u := range map[string]store.User{"plain": plain, "scoped role only": scoped, "disabled": disabled, "deleted": gone} {
		_, err = s.ApproveHardResetRequest(ctx, r.ID, u.ID, now, time.Hour)
		require.ErrorIs(t, err, store.ErrSiteAdminRequired, name)
	}
	_, err = s.ApproveHardResetRequest(ctx, r.ID, uuid.New(), now, time.Hour)
	require.ErrorIs(t, err, store.ErrSiteAdminRequired, "unknown user")
	_, err = s.ApproveHardResetRequest(ctx, uuid.New(), admin.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, admin.ID, now, time.Hour)
	require.NoError(t, err, "the request is still pending after every refusal")
}

func TestHardReset_OnlyRootRequests(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	newRoot(t, pool, s, "root")
	admin := newSiteAdmin(t, pool, s, "admin")
	now := time.Now().UTC()
	_, err := s.CreateHardResetRequest(ctx, "compliance", "x", admin.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrRootRequired, "a site-admin who is not root can't request")
}

func TestHardReset_ExpiryAndCancel(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root := newRoot(t, pool, s, "root")
	admin := newSiteAdmin(t, pool, s, "admin")
	now := time.Now().UTC()

	r, err := s.CreateHardResetRequest(ctx, "compliance", "r1", root.ID, now, 24*time.Hour)
	require.NoError(t, err)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, admin.ID, now.Add(25*time.Hour), time.Hour)
	require.ErrorIs(t, err, store.ErrHardResetState, "an unapproved request expires")

	list, err := s.ListHardResetRequests(ctx, "compliance", now.Add(25*time.Hour))
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, store.HardResetExpired, list[0].State)

	r, err = s.CreateHardResetRequest(ctx, "compliance", "r2", root.ID, now.Add(25*time.Hour), 24*time.Hour)
	require.NoError(t, err, "an expired request no longer blocks a new one")
	later := now.Add(25 * time.Hour)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, admin.ID, later, time.Hour)
	require.NoError(t, err)
	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", later.Add(2*time.Hour))
	require.ErrorIs(t, err, store.ErrHardResetState, "an approval expires")

	r, err = s.CreateHardResetRequest(ctx, "compliance", "r3", root.ID, later.Add(2*time.Hour), 24*time.Hour)
	require.NoError(t, err)
	_, err = s.CancelHardResetRequest(ctx, r.ID, admin.ID, later.Add(2*time.Hour))
	require.ErrorIs(t, err, store.ErrNotRequester, "only the requester cancels")
	r, err = s.CancelHardResetRequest(ctx, r.ID, root.ID, later.Add(2*time.Hour))
	require.NoError(t, err)
	require.Equal(t, store.HardResetCancelled, r.State)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, admin.ID, later.Add(2*time.Hour), time.Hour)
	require.ErrorIs(t, err, store.ErrHardResetState)

	types := auditTypes(t, s)
	require.Contains(t, types, "hard_reset.expired")
	require.Contains(t, types, "hard_reset.cancelled")
}

func TestHardReset_RedeemRechecksBothPeople(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root := newRoot(t, pool, s, "root")
	admin := newSiteAdmin(t, pool, s, "admin")
	now := time.Now().UTC()

	r, err := s.CreateHardResetRequest(ctx, "compliance", "x", root.ID, now, time.Hour)
	require.NoError(t, err)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, admin.ID, now, time.Hour)
	require.NoError(t, err)

	_, err = s.SetEnabled(ctx, admin.ID, false, nil, "test")
	require.NoError(t, err)
	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "an approver disabled after approving no longer counts")
	_, err = s.SetEnabled(ctx, admin.ID, true, nil, "test")
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `UPDATE users SET is_root = false WHERE id = $1`, root.ID)
	require.NoError(t, err)
	_, err = s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.ErrorIs(t, err, store.ErrHardResetState, "a requester who is no longer root no longer counts")

	_, err = pool.Exec(ctx, `UPDATE users SET is_root = true WHERE id = $1`, root.ID)
	require.NoError(t, err)
	got, err := s.ConsumeHardResetRequest(ctx, r.ID, "compliance", "reporting", now)
	require.NoError(t, err)
	require.Equal(t, store.HardResetConsumed, got.State)
}

func TestHardReset_ApprovalRefusedWhenRequesterLostRoot(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root := newRoot(t, pool, s, "root")
	admin := newSiteAdmin(t, pool, s, "admin")
	now := time.Now().UTC()
	r, err := s.CreateHardResetRequest(ctx, "compliance", "x", root.ID, now, time.Hour)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE users SET is_root = false WHERE id = $1`, root.ID)
	require.NoError(t, err)
	_, err = s.ApproveHardResetRequest(ctx, r.ID, admin.ID, now, time.Hour)
	require.ErrorIs(t, err, store.ErrHardResetState)
}
