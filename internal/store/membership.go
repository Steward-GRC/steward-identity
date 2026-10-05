// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AddUserToGroup creates a membership row (idempotent). Emits
// group.member_added on first add. The returned bool reports whether this
// call actually created the membership row (false for a no-op re-grant of an
// existing membership) — callers (e.g. the admin RPC's access-granted event)
// use it to avoid re-notifying on a repeat grant.
//
// source records provenance: SourceManual for admin / self /
// group-manager grants, SourceIdPSync for the IdP group-mapping path. An empty
// source defaults to SourceManual. A re-grant never changes an existing row's
// source (ON CONFLICT DO NOTHING) — provenance is set once, at first insert.
func (s *Store) AddUserToGroup(ctx context.Context, userID, groupID uuid.UUID,
	actor *uuid.UUID, actorExternal, source string) (bool, error) {
	if source == "" {
		source = SourceManual
	}
	if source != SourceManual && source != SourceIdPSync {
		return false, fmt.Errorf("%w: source %q", ErrInvalid, source)
	}
	var uok, gok, changed bool
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		// Existence guards so the FK error path doesn't shadow ErrNotFound.
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

		tag, err := tx.Exec(ctx,
			`INSERT INTO group_membership (user_id, group_id, added_by_user_id, source)
			 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			userID, groupID, nullableUUID(actor), source)
		if err != nil {
			return fmt.Errorf("insert membership: %w", err)
		}
		changed = tag.RowsAffected() > 0
		if changed {
			if err := s.emitAuditTx(ctx, tx, "group.member_added", actor, actorExternal,
				&userID, &groupID, map[string]any{}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return false, err
	}
	if s.agc != nil {
		s.agc.DelIdpGroups(ctx, userID.String())
	}
	return changed, nil
}

// RemoveUserFromGroup deletes a membership row (idempotent).
//
// onlyManual scopes the delete to MANUAL memberships: when true
// (a non-site-admin group-manager is acting) an existing IdP-synced membership
// is refused with ErrSyncOwned rather than removed — sync-owned rows are
// read-only to group-managers. When false (site-admin / admin CLI) any membership
// is removable. A missing membership is always an idempotent no-op regardless.
func (s *Store) RemoveUserFromGroup(ctx context.Context, userID, groupID uuid.UUID,
	actor *uuid.UUID, actorExternal string, onlyManual bool) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if onlyManual {
			var src string
			err := tx.QueryRow(ctx,
				`SELECT source FROM group_membership WHERE user_id = $1 AND group_id = $2`,
				userID, groupID).Scan(&src)
			if errors.Is(err, pgx.ErrNoRows) {
				// Nothing to remove: idempotent no-op (matches the delete path).
				return nil
			}
			if err != nil {
				return fmt.Errorf("membership source check: %w", err)
			}
			if src != SourceManual {
				return ErrSyncOwned
			}
		}

		tag, err := tx.Exec(ctx,
			`DELETE FROM group_membership WHERE user_id = $1 AND group_id = $2`,
			userID, groupID)
		if err != nil {
			return fmt.Errorf("delete membership: %w", err)
		}
		if tag.RowsAffected() > 0 {
			if err := s.emitAuditTx(ctx, tx, "group.member_removed", actor, actorExternal,
				&userID, &groupID, map[string]any{}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if s.agc != nil {
		s.agc.DelIdpGroups(ctx, userID.String())
	}
	return nil
}

// ListUsersInGroup enumerates users in a group. If includeDescendants is true,
// users in any descendant group are also included. The result is deduped on
// user id.
//
// It carries NO `deleted_at` filter, DELIBERATELY, for the same
// reason as ListUsersByIdpGroups: both tombstone writers DELETE the user's
// group_membership rows, so a tombstoned account has no row left to join
// against. Noted so a future sweep does not "fix" it.
func (s *Store) ListUsersInGroup(ctx context.Context, groupID uuid.UUID, includeDescendants bool) ([]User, error) {
	var rows pgx.Rows
	var err error
	if includeDescendants {
		rows, err = s.pool.Query(ctx, `
			WITH RECURSIVE groups_tree AS (
			  SELECT id FROM groups WHERE id = $1
			  UNION ALL
			  SELECT g.id FROM groups g JOIN groups_tree t ON g.parent_id = t.id
			)
			SELECT DISTINCT u.id, u.external_subject, u.email, u.name, u.fcm_token,
			                u.enabled, u.created_at, u.updated_at
			FROM users u
			JOIN group_membership m ON m.user_id = u.id
			WHERE m.group_id IN (SELECT id FROM groups_tree)
			ORDER BY u.email`, groupID)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT u.id, u.external_subject, u.email, u.name, u.fcm_token,
			       u.enabled, u.created_at, u.updated_at
			FROM users u
			JOIN group_membership m ON m.user_id = u.id
			WHERE m.group_id = $1
			ORDER BY u.email`, groupID)
	}
	if err != nil {
		return nil, fmt.Errorf("list users in group: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.ExternalSubject, &u.Email, &u.Name, &u.FCMToken,
			&u.Enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Hydrate all collections per user. For a list endpoint this is N+K*N
	// queries; acceptable for V1 since groups are small. Will graduate to a
	// single JOIN once roles or memberships grow.
	for i := range users {
		if err := s.hydrateUser(ctx, &users[i]); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// ListUserGroups enumerates a user's direct memberships. If
// includeDescendants is true, the result also contains every descendant of
// each direct membership (the gateway projection).
func (s *Store) ListUserGroups(ctx context.Context, userID uuid.UUID, includeDescendants bool) ([]Group, error) {
	var rows pgx.Rows
	var err error
	if includeDescendants {
		rows, err = s.pool.Query(ctx, `
			WITH RECURSIVE direct AS (
			  SELECT g.id, g.name, g.parent_id, g.metadata, g.created_at, g.updated_at
			  FROM groups g
			  JOIN group_membership m ON m.group_id = g.id
			  WHERE m.user_id = $1
			),
			expanded AS (
			  SELECT id, name, parent_id, metadata, created_at, updated_at FROM direct
			  UNION
			  SELECT g.id, g.name, g.parent_id, g.metadata, g.created_at, g.updated_at
			  FROM groups g JOIN expanded e ON g.parent_id = e.id
			)
			SELECT id, name, parent_id, metadata, created_at, updated_at
			FROM expanded ORDER BY name`, userID)
	} else {
		rows, err = s.pool.Query(ctx, `
			SELECT g.id, g.name, g.parent_id, g.metadata, g.created_at, g.updated_at
			FROM groups g JOIN group_membership m ON m.group_id = g.id
			WHERE m.user_id = $1
			ORDER BY g.name`, userID)
	}
	if err != nil {
		return nil, fmt.Errorf("list user groups: %w", err)
	}
	defer rows.Close()
	return scanGroups(rows)
}
