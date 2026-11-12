// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// rootAndPeer returns the bootstrapped root and a second live user.
func rootAndPeer(t *testing.T) (*pgxpool.Pool, *store.Store, store.User, store.User) {
	t.Helper()
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root, err := s.PreCreateLocalUserRoot(ctx, "theroot", "theroot@roots.example.org", "The Root")
	require.NoError(t, err)
	peer, err := s.PreCreateLocalUser(ctx, "peer", "peer@roots.example.org", "Peer")
	require.NoError(t, err)
	return pool, s, root, peer
}

func rootCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE is_root`).Scan(&n))
	return n
}

func TestTransferRoot_SwapsAtomicallyAndOldHolderKeepsSiteAdmin(t *testing.T) {
	pool, s, root, peer := rootAndPeer(t)
	ctx := context.Background()

	got, err := s.TransferRoot(ctx, peer.ID, &root.ID, "")
	require.NoError(t, err)
	require.Equal(t, peer.ID, got.ID)
	require.True(t, got.IsRoot)
	require.True(t, got.Enabled)
	require.Contains(t, got.Roles, "site-admin")

	old, err := s.GetUser(ctx, root.ID)
	require.NoError(t, err)
	require.False(t, old.IsRoot, "the old holder stops being root")
	require.Contains(t, old.Roles, "site-admin", "the old holder keeps site-admin")
	require.Equal(t, 1, rootCount(t, pool))

	// The old holder is now an ordinary admin: the root guards no longer apply.
	_, err = s.SetEnabled(ctx, root.ID, false, nil, "")
	require.NoError(t, err)

	// And the new root is protected.
	_, err = s.SetEnabled(ctx, peer.ID, false, nil, "")
	require.ErrorIs(t, err, store.ErrRootProtected)
}

func TestTransferRoot_EmitsRootTransferredAudit(t *testing.T) {
	_, s, root, peer := rootAndPeer(t)
	ctx := context.Background()
	_, err := s.TransferRoot(ctx, peer.ID, &root.ID, "")
	require.NoError(t, err)

	events, err := s.PendingAuditEvents(ctx, 1000)
	require.NoError(t, err)
	var found bool
	for _, e := range events {
		if e.EventType != "root.transferred" {
			continue
		}
		found = true
		require.NotNil(t, e.ActorUserID)
		require.Equal(t, root.ID, *e.ActorUserID)
		require.NotNil(t, e.TargetUserID)
		require.Equal(t, peer.ID, *e.TargetUserID)
		require.Equal(t, root.ID.String(), e.Payload["from_user_id"])
	}
	require.True(t, found, "root.transferred was not emitted")
	require.NotContains(t, auditTypes(t, s), "root.granted")
}

func TestTransferRoot_Refusals(t *testing.T) {
	pool, s, root, peer := rootAndPeer(t)
	ctx := context.Background()

	_, err := s.TransferRoot(ctx, peer.ID, nil, "")
	require.ErrorIs(t, err, store.ErrRootRequired, "no actor (CLI/mTLS) cannot transfer")

	_, err = s.TransferRoot(ctx, root.ID, &peer.ID, "")
	require.ErrorIs(t, err, store.ErrRootRequired, "a non-root actor cannot transfer")

	_, err = s.TransferRoot(ctx, root.ID, &root.ID, "")
	require.ErrorIs(t, err, store.ErrInvalid, "cannot transfer to self")

	_, err = s.TransferRoot(ctx, uuid.New(), &root.ID, "")
	require.ErrorIs(t, err, store.ErrNotFound, "missing target")

	dead, err := s.PreCreateLocalUser(ctx, "dead", "dead@roots.example.org", "Dead")
	require.NoError(t, err)
	tombstoneAndReEnable(t, pool, s, dead.ID)
	_, err = s.TransferRoot(ctx, dead.ID, &root.ID, "")
	require.ErrorIs(t, err, store.ErrNotFound, "tombstoned target")

	got, err := s.GetUser(ctx, root.ID)
	require.NoError(t, err)
	require.True(t, got.IsRoot, "a refused transfer changes nothing")
	require.Equal(t, 1, rootCount(t, pool))
}

func TestTransferRoot_EnablesDisabledTarget(t *testing.T) {
	_, s, root, peer := rootAndPeer(t)
	ctx := context.Background()
	_, err := s.SetEnabled(ctx, peer.ID, false, nil, "")
	require.NoError(t, err)
	got, err := s.TransferRoot(ctx, peer.ID, &root.ID, "")
	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.True(t, got.IsRoot)
}

func TestTransferRoot_ConcurrentTransfersLeaveOneRoot(t *testing.T) {
	pool, s, root, peer := rootAndPeer(t)
	ctx := context.Background()
	third, err := s.PreCreateLocalUser(ctx, "third", "third@roots.example.org", "Third")
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, to := range []uuid.UUID{peer.ID, third.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.TransferRoot(ctx, to, &root.ID, "")
		}()
	}
	wg.Wait()
	failed := 0
	for _, err := range errs {
		if err != nil {
			require.ErrorIs(t, err, store.ErrRootRequired)
			failed++
		}
	}
	require.Equal(t, 1, failed, "the loser no longer holds root")
	require.Equal(t, 1, rootCount(t, pool))
}

func TestUniqueIndexRejectsASecondRoot(t *testing.T) {
	pool, _, _, peer := rootAndPeer(t)
	_, err := pool.Exec(context.Background(), `UPDATE users SET is_root = true WHERE id = $1`, peer.ID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "users_single_root_idx")
}

func TestBootstrapAdmin_WorksWithTheUniqueIndex(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, created, err := s.BootstrapAdmin(ctx, "sub-boot", "boot@roots.example.org", "test")
	require.NoError(t, err)
	require.True(t, created)
	require.True(t, u.IsRoot)
	_, created, err = s.BootstrapAdmin(ctx, "sub-boot2", "boot2@roots.example.org", "test")
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, 1, rootCount(t, pool))
}

// migrationSQL reads one of the repo's migration files.
func migrationSQL(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../migrations/" + name)
	require.NoError(t, err)
	return string(b)
}

func TestMigration0002_BackfillKeepsTheOldestRootGrant(t *testing.T) {
	pool := newTestDB(t)
	ctx := context.Background()
	up := migrationSQL(t, "0002_single_root.up.sql")
	down := migrationSQL(t, "0002_single_root.down.sql")
	require.True(t, strings.Contains(up, "users_single_root_idx"))

	// Back to the 0001 shape, where several roots were allowed.
	_, err := pool.Exec(ctx, down)
	require.NoError(t, err)

	mk := func(name, created string) uuid.UUID {
		var id uuid.UUID
		require.NoError(t, pool.QueryRow(ctx,
			`INSERT INTO users (external_subject, email, is_root, created_at)
			 VALUES ($1, $2, true, $3::timestamptz) RETURNING id`,
			"sub-"+name, name+"@roots.example.org", created).Scan(&id))
		return id
	}
	grant := func(id uuid.UUID, at string) {
		_, err := pool.Exec(ctx,
			`INSERT INTO user_roles (user_id, role, scope_category, granted_at)
			 VALUES ($1, 'site-admin', '', $2::timestamptz)`, id, at)
		require.NoError(t, err)
	}
	// "young" is the oldest account but was granted last; "old" holds the
	// oldest site-admin grant; "mid" is in between. "nogrant" has no grant.
	young := mk("young", "2020-01-01")
	old := mk("old", "2022-01-01")
	mid := mk("mid", "2021-01-01")
	nogrant := mk("nogrant", "2019-01-01")
	grant(young, "2026-03-01")
	grant(old, "2024-01-01")
	grant(mid, "2025-01-01")

	_, err = pool.Exec(ctx, up)
	require.NoError(t, err)

	rows, err := pool.Query(ctx, `SELECT id FROM users WHERE is_root`)
	require.NoError(t, err)
	var roots []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		require.NoError(t, rows.Scan(&id))
		roots = append(roots, id)
	}
	rows.Close()
	require.Equal(t, []uuid.UUID{old}, roots, "the oldest root grant is kept")

	// Demoted users keep their site-admin role.
	for _, id := range []uuid.UUID{young, mid} {
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM user_roles WHERE user_id = $1 AND role = 'site-admin'`, id).Scan(&n))
		require.Equal(t, 1, n)
	}
	_ = nogrant

	_, err = pool.Exec(ctx, `UPDATE users SET is_root = true WHERE id = $1`, mid)
	require.Error(t, err, "the unique index is in place")
}

func TestMigration0002_BackfillFallsBackToOldestAccount(t *testing.T) {
	pool := newTestDB(t)
	ctx := context.Background()
	_, err := pool.Exec(ctx, migrationSQL(t, "0002_single_root.down.sql"))
	require.NoError(t, err)
	var older, newer uuid.UUID
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO users (external_subject, email, is_root, created_at)
		 VALUES ('s-new','new@roots.example.org', true, '2024-01-01') RETURNING id`).Scan(&newer))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO users (external_subject, email, is_root, created_at)
		 VALUES ('s-old','old@roots.example.org', true, '2020-01-01') RETURNING id`).Scan(&older))
	_, err = pool.Exec(ctx, migrationSQL(t, "0002_single_root.up.sql"))
	require.NoError(t, err)
	var kept uuid.UUID
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM users WHERE is_root`).Scan(&kept))
	require.Equal(t, older, kept)
}
