// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTouchSessionRecordsTheFirstUse(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedLocalUser(t, s, ctx, "dana", "dana@example.org")
	sid := uuid.New()

	wrote, err := s.TouchSession(ctx, sid, u.ID, time.Minute)
	if err != nil || !wrote {
		t.Fatalf("TouchSession: wrote=%v err=%v", wrote, err)
	}
	seen, err := s.SessionsLastSeen(ctx, []uuid.UUID{sid, uuid.New()})
	if err != nil {
		t.Fatalf("SessionsLastSeen: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("want one seen session, got %d", len(seen))
	}
	if at := seen[sid]; time.Since(at) > time.Minute {
		t.Fatalf("last seen %v is not recent", at)
	}
}

func TestTouchSessionIsThrottled(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedLocalUser(t, s, ctx, "erin", "erin@example.org")
	sid := uuid.New()

	if _, err := s.TouchSession(ctx, sid, u.ID, time.Hour); err != nil {
		t.Fatalf("first touch: %v", err)
	}
	old := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Second)
	if _, err := pool.Exec(ctx, `UPDATE session_activity SET last_seen_at = $2 WHERE session_id = $1`, sid, old); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	wrote, err := s.TouchSession(ctx, sid, u.ID, time.Hour)
	if err != nil || wrote {
		t.Fatalf("a touch inside the throttle must not write: wrote=%v err=%v", wrote, err)
	}
	seen, _ := s.SessionsLastSeen(ctx, []uuid.UUID{sid})
	if !seen[sid].Equal(old) {
		t.Fatalf("last seen moved inside the throttle: %v, want %v", seen[sid], old)
	}

	wrote, err = s.TouchSession(ctx, sid, u.ID, 10*time.Minute)
	if err != nil || !wrote {
		t.Fatalf("a touch past the throttle must write: wrote=%v err=%v", wrote, err)
	}
	seen, _ = s.SessionsLastSeen(ctx, []uuid.UUID{sid})
	if !seen[sid].After(old) {
		t.Fatalf("last seen did not move past the throttle: %v", seen[sid])
	}
}

func TestSessionsLastSeenWithNoIDs(t *testing.T) {
	s := newTestStore(t)
	seen, err := s.SessionsLastSeen(context.Background(), nil)
	if err != nil || len(seen) != 0 {
		t.Fatalf("SessionsLastSeen(nil): %v %v", seen, err)
	}
}
