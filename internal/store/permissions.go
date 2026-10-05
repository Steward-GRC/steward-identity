// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// validPermissions mirrors the CHECK constraint on user_permissions.permission.
// Only individually grantable permissions live here; role-derived permissions
// are never stored per-user.
var validPermissions = map[string]struct{}{
	"policy.read_sensitive": {},
}

// validatePermission rejects any permission outside the individually-grantable
// catalog with ErrInvalid.
func validatePermission(perm string) error {
	if _, ok := validPermissions[perm]; !ok {
		return fmt.Errorf("%w: permission %q", ErrInvalid, perm)
	}
	return nil
}

// GrantPermission grants an individual permission to a user (idempotent).
// Emits permission.granted to the outbox. Returns ErrInvalid if the permission
// is not individually grantable and ErrNotFound if the user does not exist.
// Authorization (root-only) is enforced at the handler layer.
func (s *Store) GrantPermission(ctx context.Context, userID uuid.UUID, perm string,
	actor *uuid.UUID, actorExternal string) error {
	if err := validatePermission(perm); err != nil {
		return err
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
			`INSERT INTO user_permissions (user_id, permission, granted_by_user_id)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
			userID, perm, nullableUUID(actor)); err != nil {
			return fmt.Errorf("insert permission: %w", err)
		}

		if err := s.emitAuditTx(ctx, tx, "permission.granted", actor, actorExternal,
			&userID, nil, map[string]any{"permission": perm}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// RevokePermission removes an individual permission from a user (idempotent).
// Emits permission.revoked. Returns ErrInvalid for unknown permissions and
// ErrNotFound if the user does not exist.
func (s *Store) RevokePermission(ctx context.Context, userID uuid.UUID, perm string,
	actor *uuid.UUID, actorExternal string) error {
	if err := validatePermission(perm); err != nil {
		return err
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
			`DELETE FROM user_permissions WHERE user_id = $1 AND permission = $2`,
			userID, perm); err != nil {
			return fmt.Errorf("delete permission: %w", err)
		}
		if err := s.emitAuditTx(ctx, tx, "permission.revoked", actor, actorExternal,
			&userID, nil, map[string]any{"permission": perm}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// IsRootActor reports whether the given actor (the resolved admin actor uuid)
// is the protected root account. Used by handlers to gate root-only RPCs.
// A nil actor (the admin CLI over mTLS) is treated as root, since that path
// is the operator break-glass channel.
func (s *Store) IsRootActor(ctx context.Context, actor *uuid.UUID) (bool, error) {
	if actor == nil {
		return true, nil
	}
	return s.isRoot(ctx, *actor)
}
