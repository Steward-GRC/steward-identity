// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// breakGlassRetention is how long an expired break-glass grant is retained
// before SweepBreakGlass hard-deletes it. The grant itself stops being active
// the instant it expires (see ActiveBreakGlass); retention only governs how
// long the (audited) row lingers for forensics. Zero means purge as soon as
// expired — the audit event is the permanent record.
const breakGlassRetention = 0

// GrantBreakGlass records a time-boxed break-glass reveal for userID on a single
// policy, valid for durationMin minutes from now, and emits a high-severity
// policy.break_glass_revealed audit event atomically with the grant. Returns
// the absolute expiry time. The site-admin gate is enforced at the handler.
func (s *Store) GrantBreakGlass(ctx context.Context, userID uuid.UUID,
	policyNumber, reason string, durationMin int, actor *uuid.UUID) (time.Time, error) {

	var expiresAt time.Time
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`INSERT INTO break_glass_grants (user_id, policy_number, reason, expires_at)
			   VALUES ($1, $2, $3, now() + ($4 * interval '1 minute'))
			 RETURNING expires_at`,
			userID, policyNumber, reason, durationMin,
		).Scan(&expiresAt)
		if err != nil {
			return fmt.Errorf("insert break-glass grant: %w", err)
		}

		if err := s.emitAuditTx(ctx, tx, "policy.break_glass_revealed", actor, "",
			&userID, nil, map[string]any{
				"policy_number": policyNumber,
				"reason":        reason,
				"granted_until": expiresAt.UTC().Format(time.RFC3339),
			}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return time.Time{}, err
	}
	return expiresAt, nil
}

// ActiveBreakGlass returns the policy numbers for which the given user holds an
// unexpired break-glass grant. Used by the gateway to flip an obfuscated read
// back to real content within the window.
func (s *Store) ActiveBreakGlass(ctx context.Context, userID string) ([]string, error) {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("%w: user_id %q", ErrInvalid, userID)
	}
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT policy_number FROM break_glass_grants
		  WHERE user_id = $1 AND expires_at > now()
		  ORDER BY policy_number`,
		uid)
	if err != nil {
		return nil, fmt.Errorf("list active break-glass: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var num string
		if err := rows.Scan(&num); err != nil {
			return nil, err
		}
		out = append(out, num)
	}
	return out, rows.Err()
}

// SweepBreakGlass hard-deletes break-glass grants whose expiry is older than the
// retention window. Returns the number of rows deleted. The audit trail of each
// reveal is preserved independently in the audit buffer/log.
func (s *Store) SweepBreakGlass(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM break_glass_grants
		  WHERE expires_at < now() - ($1 * interval '1 day')`,
		breakGlassRetention)
	if err != nil {
		return 0, fmt.Errorf("sweep break-glass: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
