// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/Bugs5382/go-log"
	"github.com/google/uuid"
)

// DefaultLastSeenThrottle is how often a session's last-seen time moves when
// nothing else is configured.
const DefaultLastSeenThrottle = time.Minute

// seenThrottleMax bounds the sessions one replica tracks; past it the stale
// entries are dropped.
const seenThrottleMax = 4096

// seenThrottle keeps a session that was just recorded from reaching the
// database again inside the window, so an authenticated request costs no
// write in the common case. Each replica keeps its own; the store's
// conditional update covers the rest.
type seenThrottle struct {
	mu    sync.Mutex
	every time.Duration
	now   func() time.Time
	seen  map[uuid.UUID]time.Time
}

func newSeenThrottle(every time.Duration, now func() time.Time) *seenThrottle {
	return &seenThrottle{every: every, now: now, seen: map[uuid.UUID]time.Time{}}
}

// due reports whether id should be recorded now, and if so marks it.
func (t *seenThrottle) due(id uuid.UUID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.now()
	if last, ok := t.seen[id]; ok && n.Sub(last) < t.every {
		return false
	}
	if len(t.seen) >= seenThrottleMax {
		for k, at := range t.seen {
			if n.Sub(at) >= t.every {
				delete(t.seen, k)
			}
		}
	}
	t.seen[id] = n
	return true
}

// WithLastSeenThrottle sets how often a session's last-seen time moves.
func (h *ReadHandler) WithLastSeenThrottle(every time.Duration) *ReadHandler {
	h.lastSeen = newSeenThrottle(every, time.Now)
	return h
}

// touchSession records a session as used. A failed write is logged and the
// request goes on: last-seen is informational.
func (h *ReadHandler) touchSession(ctx context.Context, sessionID, userID uuid.UUID) {
	if !h.lastSeen.due(sessionID) {
		return
	}
	lg := logger.Ctx(ctx)
	start := time.Now()
	wrote, err := h.store.TouchSession(ctx, sessionID, userID, h.lastSeen.every)
	if err != nil {
		lg.Warn("session last-seen: record failed", log.F("user_id", userID.String()), log.F("error", errText(err)))
		return
	}
	log.Trace(lg, "session last-seen: recorded", log.F("user_id", userID.String()),
		log.F("wrote", wrote), log.F("duration_ms", time.Since(start).Milliseconds()))
}
