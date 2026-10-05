// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Admin MFA factor management (the admin counterpart to the
// self-service factor management). These store ops mirror the owner-scoped
// self-service ops (DeleteTotp / DeleteWebauthnCredential / RenameTotp /
// RenameWebauthnCredential) but act on an EXPLICIT target user_id supplied by a
// site-admin, and record the acting admin as the audit actor with the target as
// the audit subject. Event types are namespaced "admin.*" so the audit trail
// distinguishes an admin-driven reset/relabel from a user's own action.
//
// Kept in a dedicated file (no edits to mfa.go / webauthn.go) so this admin
// branch never textually overlaps the unmerged self-service branch (identity!87).

// AdminTotpFactor returns the target user's TOTP enrollment state for the admin
// factor list: the confirmed-at time (nil while a pending enrollment is
// unconfirmed) and the user-facing label. ErrNotFound when the user has no TOTP
// row at all. A read-only, admin-facing companion to GetTotp that never touches
// the encrypted secret.
func (s *Store) AdminTotpFactor(ctx context.Context, userID uuid.UUID) (confirmedAt *time.Time, label string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT confirmed_at, label FROM user_totp WHERE user_id = $1`, userID,
	).Scan(&confirmedAt, &label)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrNotFound
		}
		return nil, "", fmt.Errorf("admin get totp factor: %w", err)
	}
	return confirmedAt, label, nil
}

// AdminDeleteTotp removes the target user's TOTP enrollment (a site-admin reset
// so the user can re-enroll) and emits the removal audit event atomically. actor
// is the admin's platform user id (nil on the admin CLI path) and
// actorExternal is the admin CLI operator label (empty on the gateway path); the
// target user is the audit subject. ErrNotFound when the user has no enrollment.
func (s *Store) AdminDeleteTotp(ctx context.Context, target uuid.UUID, actor *uuid.UUID, actorExternal string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, target)
		if err != nil {
			return fmt.Errorf("admin delete totp: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "admin.mfa_factor_removed", actor, actorExternal,
			&target, nil, map[string]any{"kind": "totp"}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// AdminDeleteWebauthnCredential removes one of the target user's passkeys by
// credential id (a site-admin reset) and emits the removal audit event
// atomically. Scoped by (credential_id, user_id) so a mismatched target can
// only ever miss; ErrNotFound when the user has no such credential.
func (s *Store) AdminDeleteWebauthnCredential(ctx context.Context, target uuid.UUID, credentialID string, actor *uuid.UUID, actorExternal string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM user_webauthn_credentials
			  WHERE credential_id = $1 AND user_id = $2`, credentialID, target)
		if err != nil {
			return fmt.Errorf("admin delete webauthn credential: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "admin.mfa_factor_removed", actor, actorExternal,
			&target, nil, map[string]any{
				"kind":          "passkey",
				"credential_id": credentialID,
			}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// AdminRenameTotp sets the user-facing label on the target user's TOTP
// enrollment and emits the relabel audit event atomically. An empty label clears
// it back to the client default. ErrNotFound when the user has no enrollment.
func (s *Store) AdminRenameTotp(ctx context.Context, target uuid.UUID, label string, actor *uuid.UUID, actorExternal string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE user_totp SET label = $2, updated_at = now() WHERE user_id = $1`,
			target, label)
		if err != nil {
			return fmt.Errorf("admin rename totp: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "admin.mfa_factor_relabeled", actor, actorExternal,
			&target, nil, map[string]any{"kind": "totp", "label": label}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// AdminRenameWebauthnCredential sets the user-facing label on one of the target
// user's passkeys (addressed by credential id) and emits the relabel audit event
// atomically. An empty label clears it back to the client default. Scoped by
// (credential_id, user_id); ErrNotFound when the user has no such credential.
func (s *Store) AdminRenameWebauthnCredential(ctx context.Context, target uuid.UUID, credentialID, label string, actor *uuid.UUID, actorExternal string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE user_webauthn_credentials
			    SET label = $3
			  WHERE credential_id = $1 AND user_id = $2`,
			credentialID, target, label)
		if err != nil {
			return fmt.Errorf("admin rename webauthn credential: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "admin.mfa_factor_relabeled", actor, actorExternal,
			&target, nil, map[string]any{
				"kind":          "passkey",
				"credential_id": credentialID,
				"label":         label,
			}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
