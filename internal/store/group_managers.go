// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GrantGroupManager records a LOCAL group-manager grant for (userID, groupID)
// . Idempotent: a re-grant is a no-op that still emits the audit
// event so the attempt is recorded (mirrors GrantRole). Existence of both the
// user and the group is verified first so the FK error path doesn't shadow
// ErrNotFound. The grant is NEVER sourced from the IdP — it is a per-group
// local authority to manage MANUAL memberships, not a scoped role.
func (s *Store) GrantGroupManager(ctx context.Context, userID, groupID uuid.UUID,
	actor *uuid.UUID, actorExternal string) error {
	return s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var uok, gok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&uok); err != nil {
			return fmt.Errorf("user check: %w", err)
		}
		if !uok {
			return fmt.Errorf("%w: user_id", ErrNotFound)
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1)`, groupID).Scan(&gok); err != nil {
			return fmt.Errorf("group check: %w", err)
		}
		if !gok {
			return fmt.Errorf("%w: group_id", ErrNotFound)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO group_managers (user_id, group_id, granted_by_user_id)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			userID, groupID, nullableUUID(actor)); err != nil {
			return fmt.Errorf("insert group manager: %w", err)
		}
		if err := s.emitAuditTx(ctx, tx, "group.manager_granted", actor, actorExternal,
			&userID, &groupID, map[string]any{}); err != nil {
			return err
		}
		return nil
	})
}

// RevokeGroupManager removes a group-manager grant. Idempotent:
// a delete of a non-existent grant still commits (and emits) as a no-op.
func (s *Store) RevokeGroupManager(ctx context.Context, userID, groupID uuid.UUID,
	actor *uuid.UUID, actorExternal string) error {
	return s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM group_managers WHERE user_id = $1 AND group_id = $2`,
			userID, groupID)
		if err != nil {
			return fmt.Errorf("delete group manager: %w", err)
		}
		if tag.RowsAffected() > 0 {
			if err := s.emitAuditTx(ctx, tx, "group.manager_revoked", actor, actorExternal,
				&userID, &groupID, map[string]any{}); err != nil {
				return err
			}
		}
		return nil
	})
}

// IsGroupManager reports whether userID holds a group-manager grant on groupID.
// It is the authorization primitive the membership handlers use to admit a
// non-site-admin group-manager.
func (s *Store) IsGroupManager(ctx context.Context, userID, groupID uuid.UUID) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM group_managers WHERE user_id = $1 AND group_id = $2)`,
		userID, groupID).Scan(&ok); err != nil {
		return false, fmt.Errorf("is group manager: %w", err)
	}
	return ok, nil
}

// ListManagedGroups returns the group ids userID is a LOCAL group-manager of,
// ordered by group id. Empty slice when the user manages none.
func (s *Store) ListManagedGroups(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	if err := s.loadInto(ctx, userID, &out,
		`SELECT group_id FROM group_managers WHERE user_id=$1 ORDER BY group_id`); err != nil {
		return nil, err
	}
	return out, nil
}
