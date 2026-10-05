// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"context"
	"testing"
	"time"

	redis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/cache"
)

func connect(t *testing.T) (*miniredis.Miniredis, *cache.Redis) {
	t.Helper()
	srv := miniredis.RunT(t)
	c, err := redis.Connect(context.Background(), redis.WithAddr(srv.Addr()),
		redis.WithTimeouts(200*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond), redis.WithRetry(1, time.Millisecond, time.Millisecond))
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return srv, cache.New(c, time.Minute)
}

func TestIdpGroupsRoundTrip(t *testing.T) {
	srv, r := connect(t)
	ctx := context.Background()
	_, ok := r.GetIdpGroups(ctx, "u1")
	require.False(t, ok, "an empty cache misses")

	r.SetIdpGroups(ctx, "u1", []string{"Finance team", "All staff"})
	got, ok := r.GetIdpGroups(ctx, "u1")
	require.True(t, ok)
	require.Equal(t, []string{"Finance team", "All staff"}, got)
	require.Equal(t, time.Minute, srv.TTL("idpgroups:u1"))

	r.SetIdpGroups(ctx, "u2", []string{})
	got, ok = r.GetIdpGroups(ctx, "u2")
	require.True(t, ok, "an empty list is a hit")
	require.Empty(t, got)

	r.DelIdpGroups(ctx, "u1")
	_, ok = r.GetIdpGroups(ctx, "u1")
	require.False(t, ok)
}

func TestAnOutageDegradesToMisses(t *testing.T) {
	srv, r := connect(t)
	ctx := context.Background()
	r.SetIdpGroups(ctx, "u1", []string{"All staff"})
	srv.Close()
	for range 5 {
		_, ok := r.GetIdpGroups(ctx, "u1")
		require.False(t, ok, "a cache that can't be reached reads as a miss")
	}
	start := time.Now()
	_, ok := r.GetIdpGroups(ctx, "u1")
	require.False(t, ok)
	require.Less(t, time.Since(start), 50*time.Millisecond, "after repeated failures the breaker skips Redis")
}
