// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CountUsersByIdpGroups returns the number of distinct users that belong to any
// of the given AD group names. An empty names slice returns 0 immediately
// (avoids a WHERE IN () that some drivers reject).
func (s *Store) CountUsersByIdpGroups(ctx context.Context, names []string) (int, error) {
	if len(names) == 0 {
		return 0, nil
	}
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(DISTINCT user_id) FROM user_idp_groups WHERE idp_group_name = ANY($1)`,
		names,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users by ad groups: %w", err)
	}
	return n, nil
}

// ListUsersByIdpGroups returns all distinct users that belong to any of the
// given AD group names, with roles and AD-group memberships hydrated. An empty
// names slice returns an empty (non-nil) slice immediately.
//
// It carries NO `deleted_at` filter, DELIBERATELY. Both tombstone
// writers (DeleteUser, TombstoneMergedSource) DELETE the user's user_idp_groups
// rows, so a tombstoned account has nothing left to join against and is
// structurally absent. Adding a redundant predicate here would suggest the join
// were the weak link; it is not. Noted so a future sweep does not "fix" it.
func (s *Store) ListUsersByIdpGroups(ctx context.Context, names []string) ([]User, error) {
	if len(names) == 0 {
		return []User{}, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT u.id, u.external_subject, u.email, u.name, u.fcm_token,
		                u.enabled, u.created_at, u.updated_at
		FROM users u
		JOIN user_idp_groups uag ON uag.user_id = u.id
		WHERE uag.idp_group_name = ANY($1)
		ORDER BY u.email`, names)
	if err != nil {
		return nil, fmt.Errorf("list users by ad groups: %w", err)
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
	// Hydrate roles/idpGroups/exclusions/overrides for each user — same pattern
	// as ListUsersInGroup and ListUsersByEmail.
	for i := range users {
		if err := s.hydrateUser(ctx, &users[i]); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// CountAllUsers returns the number of ENABLED, non-deleted platform users. This
// is the audience size when a policy/group ack targets "Everyone".
//
// `deleted_at IS NULL` is EXPLICIT. Before, the `enabled = true`
// filter excluded tombstones only because both tombstone writers also set
// enabled = false — correct today, but resting on a coincidence rather than on
// intent, and TransferRoot already re-enables its target unconditionally.
func (s *Store) CountAllUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE enabled = true AND deleted_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count all users: %w", err)
	}
	return n, nil
}

// ListAllUsers returns all ENABLED, non-deleted platform users, with roles and
// memberships hydrated. This is the audience when a policy/group ack targets
// "Everyone". See CountAllUsers for why `deleted_at IS NULL` is explicit
// ; the two MUST agree or the audience size and the audience
// roster disagree.
func (s *Store) ListAllUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.external_subject, u.email, u.name, u.fcm_token,
		       u.enabled, u.created_at, u.updated_at
		FROM users u
		WHERE u.enabled = true AND u.deleted_at IS NULL
		ORDER BY u.email`)
	if err != nil {
		return nil, fmt.Errorf("list all users: %w", err)
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
	// Hydrate roles/idpGroups/exclusions/overrides for each user — same pattern
	// as ListUsersByIdpGroups.
	for i := range users {
		if err := s.hydrateUser(ctx, &users[i]); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// UserIdpGroups returns the AD group names for a single user, keyed by the
// platform user id (user_idp_groups.user_id). Returns an empty (non-nil) slice
// when the user has no AD groups or does not exist.
func (s *Store) UserIdpGroups(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if s.agc != nil {
		if names, ok := s.agc.GetIdpGroups(ctx, userID.String()); ok {
			return names, nil
		}
	}
	var names []string
	if err := s.loadStrings(ctx, userID, &names,
		`SELECT idp_group_name FROM user_idp_groups WHERE user_id=$1 ORDER BY idp_group_name`); err != nil {
		return nil, fmt.Errorf("user ad groups: %w", err)
	}
	if s.agc != nil {
		s.agc.SetIdpGroups(ctx, userID.String(), names)
	}
	return names, nil
}

// ReplaceUserIdpGroups atomically replaces the full set of AD group names for a
// user. No audit event is emitted — this is a high-frequency sync-driven path.
func (s *Store) ReplaceUserIdpGroups(ctx context.Context, userID uuid.UUID, names []string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM user_idp_groups WHERE user_id=$1`, userID); err != nil {
			return fmt.Errorf("clear ad groups: %w", err)
		}
		for _, n := range names {
			if _, err := tx.Exec(ctx,
				`INSERT INTO user_idp_groups (user_id, idp_group_name) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
				userID, n); err != nil {
				return fmt.Errorf("insert ad group: %w", err)
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

// SetPolicyOverride sets or clears a per-user allow/deny override for a policy
// number. effect="" clears the override; effect must otherwise be "allow" or
// "deny". Emits user.policy_override_set or user.policy_override_cleared.
// Returns ErrInvalid for an unknown effect value and ErrNotFound when the user
// does not exist.
func (s *Store) SetPolicyOverride(ctx context.Context, userID uuid.UUID,
	policyNumber, effect string, actor *uuid.UUID, actorExternal string) (User, error) {

	if effect != "" && effect != "allow" && effect != "deny" {
		return User{}, fmt.Errorf("%w: effect must be 'allow', 'deny', or empty", ErrInvalid)
	}

	var exists bool
	var eventType string
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, userID).Scan(&exists); err != nil {
			return fmt.Errorf("user exists check: %w", err)
		}
		if !exists {
			return ErrNotFound
		}

		if effect == "" {
			if _, err := tx.Exec(ctx,
				`DELETE FROM user_policy_overrides WHERE user_id=$1 AND policy_number=$2`,
				userID, policyNumber); err != nil {
				return fmt.Errorf("delete override: %w", err)
			}
			eventType = "user.policy_override_cleared"
		} else {
			if _, err := tx.Exec(ctx,
				`INSERT INTO user_policy_overrides (user_id, policy_number, effect)
				 VALUES ($1,$2,$3)
				 ON CONFLICT (user_id, policy_number) DO UPDATE SET effect=EXCLUDED.effect`,
				userID, policyNumber, effect); err != nil {
				return fmt.Errorf("upsert override: %w", err)
			}
			eventType = "user.policy_override_set"
		}

		if err := s.emitAuditTx(ctx, tx, eventType, actor, actorExternal,
			&userID, nil, map[string]any{"policy_number": policyNumber, "effect": effect}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, userID)
}
