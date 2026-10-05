// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// deletedAccessTables is the list of identity-owned access-row tables that
// DeleteUser drops with the account, in delete order.
//
// It is a package-level var, shared by DeleteUser and by
// UserDeletionPreflight's counter, ON PURPOSE: a delete preview
// that reports a different set of tables from the one the delete actually
// clears is worse than no preview, because an admin would trust it. Adding a
// table to the delete now automatically adds it to the preview, and
// TestDeletionPreflightCoversEveryDeletedTable fails if the two ever diverge.
//
// group_managers is NOT in this list, and that is not an omission — DeleteUser
// genuinely does not touch it. See UserAccessRowCounts.ManagedGroups.
var deletedAccessTables = []string{
	"group_membership",
	"user_idp_groups",
	"user_roles",
	"user_permissions",
	"user_policy_overrides",
	"break_glass_grants",
}

// UserAccessRowCounts is the number of identity-owned access rows a delete of
// one account would drop, counted per table straight from the tables
// DeleteUser clears.
//
// The counts are raw row counts, NOT the hydrated projections on User:
//
//   - BreakGlassGrants: this one genuinely differs TODAY. ActiveBreakGlass
//     filters `expires_at > now()` and applies `DISTINCT policy_number`, while
//     DeleteUser deletes every row in break_glass_grants unconditionally, and
//     the table has a BIGSERIAL id with no uniqueness on
//     (user_id, policy_number) — so expired-but-unswept grants and repeat
//     grants of the same policy are real rows the delete removes and
//     ActiveBreakGlass cannot see. Counting from it would under-report.
//   - Permissions: this one currently AGREES with hydrateUser's
//     `EXISTS(... permission = 'policy.read_sensitive')` bool, because
//     user_permissions is PRIMARY KEY (user_id, permission) with
//     CHECK (permission IN ('policy.read_sensitive')) — so an account can hold
//     at most that one row. It is counted from the table anyway because
//     DeleteUser deletes ROWS, not a bool: the day that CHECK widens (it is the
//     obvious place a second individually-grantable permission lands), the bool
//     silently starts under-reporting and this count does not.
type UserAccessRowCounts struct {
	GroupMemberships int
	IdpGroups        int
	Roles            int
	Permissions      int
	PolicyOverrides  int
	BreakGlassGrants int
	// ManagedGroups is the number of groups the account is a LOCAL
	// group-manager of. It is reported alongside the others but is NOT dropped
	// by the delete: DeleteUser does not touch group_managers, so a deleted
	// account keeps its manager grants as rows pointing at a tombstone. The
	// preview says so rather than implying they are cleaned up.
	ManagedGroups int
}

// tableToCount maps a deletedAccessTables entry to the field it fills. Kept
// beside the table list so a new table without a field is a loud failure
// (UserAccessRowCounts returns an error) rather than a silently missing count.
func (c *UserAccessRowCounts) fieldFor(table string) (*int, bool) {
	switch table {
	case "group_membership":
		return &c.GroupMemberships, true
	case "user_idp_groups":
		return &c.IdpGroups, true
	case "user_roles":
		return &c.Roles, true
	case "user_permissions":
		return &c.Permissions, true
	case "user_policy_overrides":
		return &c.PolicyOverrides, true
	case "break_glass_grants":
		return &c.BreakGlassGrants, true
	}
	return nil, false
}

// UserDeletionPreflight is everything the delete preview needs from identity's
// own database, gathered in one read-only pass. Nothing here
// mutates.
type UserDeletionPreflight struct {
	User       User
	AccessRows UserAccessRowCounts
	// Passkeys is the number of registered WebAuthn credentials. Together with
	// User.LocalAccount it is identity's own half of "can this account
	// authenticate without the IdP"; the credential store's half comes from the
	// Kratos lookup in internal/userdelete.
	Passkeys int
	// GroupLabels names the account's group memberships so the preview can show
	// "Finance" instead of a bare UUID.
	GroupLabels map[uuid.UUID]string
	// Permissions are the account's individual permission grants by name.
	Permissions []string
	// OtherLiveAccountsSameEmail counts LIVE accounts other than this one that
	// share this email address, and how many of those are locally-authenticable.
	//
	// This is the computable half of the note that motivated the
	// preview: "deleting a user's only locally-authenticable account changes how
	// they can get in." Identity cannot know that two accounts are the same
	// PERSON — only that they share an address — so the preview reports exactly
	// that and does not pretend to more.
	OtherLiveAccountsSameEmail  int
	OtherLocalAccountsSameEmail int
}

// UserAccessRowCounts counts the account's identity-owned access rows by
// walking deletedAccessTables — the same list DeleteUser deletes from — plus
// group_managers, which the delete leaves behind.
func (s *Store) UserAccessRowCounts(ctx context.Context, id uuid.UUID) (UserAccessRowCounts, error) {
	var out UserAccessRowCounts
	for _, table := range deletedAccessTables {
		field, ok := out.fieldFor(table)
		if !ok {
			// A table was added to deletedAccessTables without a count field.
			// Fail loudly: silently returning a short count would make the
			// preview under-report what the delete removes.
			return UserAccessRowCounts{}, fmt.Errorf(
				"user access row counts: table %q has no count field — add one to UserAccessRowCounts", table)
		}
		// table comes from a package-level literal list, never from input.
		if err := s.pool.QueryRow(ctx,
			`SELECT count(*) FROM `+table+` WHERE user_id = $1`, id).Scan(field); err != nil {
			return UserAccessRowCounts{}, fmt.Errorf("count %s: %w", table, err)
		}
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM group_managers WHERE user_id = $1`, id).Scan(&out.ManagedGroups); err != nil {
		return UserAccessRowCounts{}, fmt.Errorf("count group_managers: %w", err)
	}
	return out, nil
}

// DeletedAccessTables returns the tables DeleteUser clears, for tests and for
// anything that must stay in step with the delete. The copy is defensive.
func DeletedAccessTables() []string {
	return append([]string(nil), deletedAccessTables...)
}

// ListUserPermissions returns the account's individual permission grants by
// name, ordered. hydrateUser cannot answer this: it probes only
// policy.read_sensitive as a bool, while DeleteUser deletes every row in
// user_permissions.
func (s *Store) ListUserPermissions(ctx context.Context, id uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT permission FROM user_permissions WHERE user_id = $1 ORDER BY permission`, id)
	if err != nil {
		return nil, fmt.Errorf("list user permissions: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// UserDeletionPreflight gathers, read-only, everything the delete preview needs
// from identity's own database. Returns ErrNotFound when no such
// user exists.
//
// An ALREADY-TOMBSTONED account is a legitimate input and is returned with
// User.DeletedAt set: previewing a delete of an account that is already deleted
// should say so, not 404.
func (s *Store) UserDeletionPreflight(ctx context.Context, id uuid.UUID) (UserDeletionPreflight, error) {
	u, err := s.GetUser(ctx, id)
	if err != nil {
		return UserDeletionPreflight{}, err
	}
	out := UserDeletionPreflight{User: u}

	if out.AccessRows, err = s.UserAccessRowCounts(ctx, id); err != nil {
		return UserDeletionPreflight{}, err
	}
	if out.Permissions, err = s.ListUserPermissions(ctx, id); err != nil {
		return UserDeletionPreflight{}, err
	}
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM user_webauthn_credentials WHERE user_id = $1`, id,
	).Scan(&out.Passkeys); err != nil {
		return UserDeletionPreflight{}, fmt.Errorf("count passkeys: %w", err)
	}

	// Group names for the preview's item labels. Best-effort in spirit but an
	// error is still returned: the preview fails closed rather than showing a
	// partial picture.
	out.GroupLabels = map[uuid.UUID]string{}
	if len(u.Groups) > 0 {
		rows, err := s.pool.Query(ctx,
			`SELECT id, name FROM groups WHERE id = ANY($1)`, u.Groups)
		if err != nil {
			return UserDeletionPreflight{}, fmt.Errorf("resolve group labels: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var gid uuid.UUID
			var name string
			if err := rows.Scan(&gid, &name); err != nil {
				return UserDeletionPreflight{}, err
			}
			out.GroupLabels[gid] = name
		}
		if err := rows.Err(); err != nil {
			return UserDeletionPreflight{}, err
		}
	}

	// Other LIVE accounts on the same address, and how many can authenticate
	// locally. `local_account OR a passkey` is identity's own definition of
	// locally-authenticable; the Kratos credential is checked separately by the
	// preview, because identity does not own that store.
	if err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*),
		  count(*) FILTER (
		    WHERE u.local_account
		       OR EXISTS(SELECT 1 FROM user_webauthn_credentials w WHERE w.user_id = u.id))
		  FROM users u
		 WHERE lower(u.email) = lower($2)
		   AND u.id <> $1
		   AND u.deleted_at IS NULL`,
		id, u.Email,
	).Scan(&out.OtherLiveAccountsSameEmail, &out.OtherLocalAccountsSameEmail); err != nil {
		return UserDeletionPreflight{}, fmt.Errorf("count sibling accounts: %w", err)
	}
	return out, nil
}
