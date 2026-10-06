// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// TouchSession records that a sign-in session was just used. A session seen
// within the last throttle keeps its time and nothing is written; wrote says
// whether the row changed.
func (s *Store) TouchSession(ctx context.Context, sessionID, userID uuid.UUID, throttle time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO session_activity (session_id, user_id) VALUES ($1, $2)
		 ON CONFLICT (session_id) DO UPDATE SET last_seen_at = now()
		  WHERE session_activity.last_seen_at < now() - $3::interval`,
		sessionID, userID, throttle.String())
	if err != nil {
		return false, fmt.Errorf("touch session: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SessionsLastSeen returns the last use of each given session that has one;
// a session never seen is absent from the map.
func (s *Store) SessionsLastSeen(ctx context.Context, sessionIDs []uuid.UUID) (map[uuid.UUID]time.Time, error) {
	out := make(map[uuid.UUID]time.Time, len(sessionIDs))
	if len(sessionIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT session_id, last_seen_at FROM session_activity WHERE session_id = ANY($1)`, sessionIDs)
	if err != nil {
		return nil, fmt.Errorf("sessions last seen: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("scan session last seen: %w", err)
		}
		out[id] = at
	}
	return out, rows.Err()
}
