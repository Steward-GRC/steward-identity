// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSeenThrottleSkipsRepeatsInsideTheWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	th := newSeenThrottle(time.Minute, func() time.Time { return now })
	a, b := uuid.New(), uuid.New()

	if !th.due(a) {
		t.Fatal("first sight must be due")
	}
	if th.due(a) {
		t.Fatal("a repeat inside the window must not be due")
	}
	if !th.due(b) {
		t.Fatal("another session is tracked on its own")
	}
	now = now.Add(time.Minute)
	if !th.due(a) {
		t.Fatal("due again once the window has passed")
	}
}

func TestSeenThrottleDropsStaleEntriesWhenFull(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	th := newSeenThrottle(time.Minute, func() time.Time { return now })
	for range seenThrottleMax {
		th.due(uuid.New())
	}
	now = now.Add(2 * time.Minute)
	th.due(uuid.New())
	if n := len(th.seen); n != 1 {
		t.Fatalf("stale entries kept: %d tracked, want 1", n)
	}
}
