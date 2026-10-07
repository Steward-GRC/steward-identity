// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// validRoles mirrors the CHECK constraint on user_roles.role (the 6 storable
// roles; reader is implicit and never stored).
var validRoles = map[string]struct{}{
	"author": {}, "approver": {},
	"site-admin": {}, "template-admin": {}, "compliance-admin": {},
}

// scopedRoles are the roles that REQUIRE a non-empty category; all others
// must have an empty category.
var scopedRoles = map[string]struct{}{"author": {}, "approver": {}}

// validateRoleScope enforces the category rule: author/approver need a
// non-empty category; global roles must not carry one.
func validateRoleScope(role, category string) error {
	if _, ok := validRoles[role]; !ok {
		return fmt.Errorf("%w: role %q", ErrInvalid, role)
	}
	_, scoped := scopedRoles[role]
	if scoped && category == "" {
		return fmt.Errorf("%w: role %q requires a category", ErrInvalid, role)
	}
	if !scoped && category != "" {
		return fmt.Errorf("%w: role %q must not have a category", ErrInvalid, role)
	}
	return nil
}

// GrantRole adds a role to a user (idempotent). Emits role.granted to the
// outbox. Returns ErrInvalid if the role is not one of the canonical set or
// if the category constraint is violated (scoped roles need a category; global
// roles must not have one).
func (s *Store) GrantRole(ctx context.Context, userID uuid.UUID, role, category string,
	actor *uuid.UUID, actorExternal string) (User, error) {
	if err := validateRoleScope(role, category); err != nil {
		return User{}, err
	}

	var exists bool
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		// Verify the user exists; otherwise the FK error from the role insert
		// is ambiguous with a duplicate-key collision.
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
			return fmt.Errorf("user exists check: %w", err)
		}
		if !exists {
			return ErrNotFound
		}

		tag, err := tx.Exec(ctx,
			`INSERT INTO user_roles (user_id, role, scope_category, granted_by_user_id)
			 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			userID, role, category, nullableUUID(actor))
		if err != nil {
			return fmt.Errorf("insert role: %w", err)
		}
		// Even if it was a no-op (already had the role) we still emit so the
		// audit trail records the attempt; idempotency is at the data layer.
		_ = tag

		if err := s.emitAuditTx(ctx, tx, "role.granted", actor, actorExternal,
			&userID, nil, map[string]any{"role": role, "category": category}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, userID)
}

// RevokeRole removes a role from a user (idempotent). Emits role.revoked.
func (s *Store) RevokeRole(ctx context.Context, userID uuid.UUID, role, category string,
	actor *uuid.UUID, actorExternal string) (User, error) {
	if err := validateRoleScope(role, category); err != nil {
		return User{}, err
	}
	// A root admin must keep the global site-admin role; stripping it would
	// lock them out. Revoke root first.
	if category == "" && role == "site-admin" {
		root, err := s.isRoot(ctx, userID)
		if err != nil {
			return User{}, err
		}
		if root {
			return User{}, fmt.Errorf("%w: cannot revoke %q from the root account", ErrRootProtected, role)
		}
	}
	var exists bool
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
			return fmt.Errorf("user exists check: %w", err)
		}
		if !exists {
			return ErrNotFound
		}

		if _, err := tx.Exec(ctx,
			`DELETE FROM user_roles WHERE user_id = $1 AND role = $2 AND scope_category = $3`,
			userID, role, category); err != nil {
			return fmt.Errorf("delete role: %w", err)
		}
		if err := s.emitAuditTx(ctx, tx, "role.revoked", actor, actorExternal,
			&userID, nil, map[string]any{"role": role, "category": category}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, userID)
}

// AdminExists reports whether any user holds the `site-admin` role. Used by
// BootstrapInitialAdmin to enforce its "succeeds only when no admin exists"
// idempotency.
func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_roles WHERE role = 'site-admin')`).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("admin exists: %w", err)
	}
	return exists, nil
}

// BootstrapAdmin creates a user (if needed) with the admin role. Idempotent
// in two senses: re-running with the same external_subject is fine, and if
// an admin already exists the function returns the existing user untouched
// with created=false.
func (s *Store) BootstrapAdmin(ctx context.Context, externalSub, email string,
	actorExternal string) (User, bool, error) {
	var u User
	existing := false
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		existing = false
		if err := lockRootSet(ctx, tx); err != nil {
			return err
		}
		// The EXISTS probe and the row fetch below MUST use the same predicate: if
		// the probe counted a tombstoned admin the fetch would then find no row and
		// bootstrap would fail with "load existing admin: no rows" instead of
		// creating one.
		var adminExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(
		    SELECT 1 FROM user_roles r
		      JOIN users u ON u.id = r.user_id
		     WHERE r.role = 'site-admin' AND u.deleted_at IS NULL)`).Scan(&adminExists); err != nil {
			return fmt.Errorf("admin exists: %w", err)
		}
		if adminExists {
			// Return whatever LIVE admin exists (oldest grant first) so callers have
			// something concrete to point at; the `created` flag distinguishes the
			// no-op.
			//
			// `u.deleted_at IS NULL` is explicit. A tombstoned admin
			// is not an admin: reporting one as the existing admin would make a
			// cluster whose only admin had been deleted look provisioned while being
			// unadministrable. It is unreachable today only because both tombstone
			// writers also DELETE user_roles, which is what makes the EXISTS above
			// false — another safety-by-coincidence.
			u = User{}
			err := tx.QueryRow(ctx,
				`SELECT u.id, u.external_subject, u.email, u.name, u.fcm_token, u.enabled,
			        u.created_at, u.updated_at
			 FROM users u
			 JOIN user_roles r ON r.user_id = u.id
			 WHERE r.role = 'site-admin'
			   AND u.deleted_at IS NULL
			 ORDER BY r.granted_at ASC
			 LIMIT 1`,
			).Scan(&u.ID, &u.ExternalSubject, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
			if err != nil {
				return fmt.Errorf("load existing admin: %w", err)
			}
			existing = true
			return nil
		}

		u = User{}
		u.ExternalSubject = externalSub
		u.Email = email
		// The first admin is also the protected root and gets the global
		// site-admin role (the dropped 'admin' role no longer exists).
		err := tx.QueryRow(ctx,
			`INSERT INTO users (external_subject, email, is_root) VALUES ($1, $2, true)
		   ON CONFLICT (external_subject) WHERE external_subject <> '' DO UPDATE SET email = EXCLUDED.email, is_root = true, updated_at = now()
		 RETURNING id, name, fcm_token, enabled, created_at, updated_at`,
			externalSub, email,
		).Scan(&u.ID, &u.Name, &u.FCMToken, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			return fmt.Errorf("insert user: %w", err)
		}

		// Grant site-admin (global, empty scope); reader is implicit.
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '')
		   ON CONFLICT DO NOTHING`, u.ID); err != nil {
			return fmt.Errorf("grant site-admin: %w", err)
		}

		if err := s.emitAuditTx(ctx, tx, "user.created", nil, actorExternal, &u.ID, nil, map[string]any{"email": email, "bootstrap": true}); err != nil {
			return err
		}
		if err := s.emitAuditTx(ctx, tx, "role.granted", nil, actorExternal, &u.ID, nil, map[string]any{"role": "site-admin", "category": "", "bootstrap": true}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return User{}, false, err
	}
	full, err := s.GetUser(ctx, u.ID)
	if err != nil {
		return User{}, false, err
	}
	return full, !existing, nil
}

// HasRootUser reports whether any is_root user exists (drives first-run setup).
//
// No `deleted_at` filter, DELIBERATELY: root cannot be tombstoned
// at all — DeleteUser and TombstoneMergedSource both refuse with
// ErrRootProtected — so a deleted is_root row cannot exist. That is a real
// invariant, enforced in code, not a coincidence like the enabled=false ones.
func (s *Store) HasRootUser(ctx context.Context) (bool, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE is_root)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("HasRootUser: %w", err)
	}
	return exists, nil
}

// isRoot reports whether the given user is the protected root account.
// Missing users report false (callers surface ErrNotFound through their own
// existence checks / RowsAffected handling).
//
// No `deleted_at` filter, DELIBERATELY, and here it MUST NOT have
// one: this is the root-protection guard for SetEnabled / DeleteUser /
// RevokeRole / TombstoneMergedSource. Filtering it would make the guard stop
// firing for an already-tombstoned row, so a re-delete of the root would go
// through instead of being refused.
func (s *Store) isRoot(ctx context.Context, id uuid.UUID) (bool, error) {
	var root bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND is_root)`, id).Scan(&root); err != nil {
		return false, fmt.Errorf("is_root check: %w", err)
	}
	return root, nil
}

// rootSetLock is the transaction-scoped advisory lock every change to the set
// of root admins takes, so the "no root yet" and "last root" checks can't race.
const rootSetLock = 7_314_201_611

func lockRootSet(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(rootSetLock)); err != nil {
		return fmt.Errorf("lock root admins: %w", err)
	}
	return nil
}

// GrantRoot makes a user a root admin as well: it sets is_root, ensures the
// account is enabled and grants the global site-admin role (lockout-safe).
// Granting it again is a no-op that still answers with the user.
//
// The target MUST be a LIVE account. GrantRoot sets enabled = true
// unconditionally; granting root to a tombstoned row would manufacture the
// enabled tombstone that every tombstone-blind query relies on not existing,
// and make a root admin a deleted account, which nothing could then undo
// because a root can't be deleted. A tombstoned target returns ErrNotFound.
func (s *Store) GrantRoot(ctx context.Context, userID uuid.UUID, actor *uuid.UUID, actorExternal string) (User, error) {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := lockRootSet(ctx, tx); err != nil {
			return err
		}
		var exists, already bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL),
			        EXISTS(SELECT 1 FROM users WHERE id = $1 AND is_root)`,
			userID).Scan(&exists, &already); err != nil {
			return fmt.Errorf("target exists check: %w", err)
		}
		if !exists {
			return ErrNotFound
		}
		if already {
			return nil
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET is_root = true, enabled = true, updated_at = now() WHERE id = $1`, userID); err != nil {
			return fmt.Errorf("set root: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '')
			   ON CONFLICT DO NOTHING`, userID); err != nil {
			return fmt.Errorf("grant site-admin: %w", err)
		}
		return s.emitAuditTx(ctx, tx, "root.granted", actor, actorExternal, &userID, nil, map[string]any{})
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, userID)
}

// RevokeRoot takes the root role from a user, who keeps site-admin. The last
// root admin can't lose it (ErrRootProtected); a user who isn't root is
// ErrInvalid. Concurrent revokes are serialised, so at least one root always
// remains.
func (s *Store) RevokeRoot(ctx context.Context, userID uuid.UUID, actor *uuid.UUID, actorExternal string) (User, error) {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := lockRootSet(ctx, tx); err != nil {
			return err
		}
		var isRoot bool
		var roots int
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND is_root),
			        (SELECT count(*) FROM users WHERE is_root)`,
			userID).Scan(&isRoot, &roots); err != nil {
			return fmt.Errorf("root count: %w", err)
		}
		if !isRoot {
			return fmt.Errorf("%w: the user isn't a root admin", ErrInvalid)
		}
		if roots <= 1 {
			return fmt.Errorf("%w: cannot revoke root from the last root admin", ErrRootProtected)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET is_root = false, updated_at = now() WHERE id = $1`, userID); err != nil {
			return fmt.Errorf("clear root: %w", err)
		}
		return s.emitAuditTx(ctx, tx, "root.revoked", actor, actorExternal, &userID, nil, map[string]any{})
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, userID)
}
