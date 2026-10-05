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

// MFA second factors, Phase 2: WebAuthn/FIDO2 passkeys. Two tables:
// user_webauthn_credentials holds the registered credentials (PUBLIC key
// material only — the private key never leaves the authenticator, so nothing
// here needs at-rest encryption), and webauthn_sessions bridges the
// begin/finish halves of a ceremony with a short-lived, single-use,
// server-side challenge session. The handlers own the go-webauthn relying
// party; the store persists opaque blobs (COSE public key bytes, SessionData
// JSON) plus the metadata the factor-management surface lists.

// WebAuthn ceremony purposes. Handlers validate against this closed set so
// the purpose column stays a controlled vocabulary, and a register session
// can never be spent on an assert (or vice versa).
const (
	// WebauthnPurposeRegister is a credential-registration ceremony.
	WebauthnPurposeRegister = "register"
	// WebauthnPurposeAssert is an assertion (login) ceremony.
	WebauthnPurposeAssert = "assert"
)

// webauthnSessionTTL bounds the begin→finish window (5 min per the design
// spec — same order as the email-OTP TTL).
const webauthnSessionTTL = 5 * time.Minute

// WebauthnCredential is a registered passkey row. CredentialID is the
// authenticator-issued credential id, base64url (unpadded). SignCount is the
// last authenticator signature counter seen; AAGUID/Transports/Backup* are
// registration-time metadata.
type WebauthnCredential struct {
	CredentialID   string
	UserID         uuid.UUID
	PublicKey      []byte
	SignCount      int64
	AAGUID         []byte
	Transports     []string
	BackupEligible bool
	BackupState    bool
	Label          string
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// CreateWebauthnSession opens the server-side challenge session for a
// begin call: it replaces any live session the user already has for the same
// purpose (one in-flight ceremony per purpose), prunes expired leftovers,
// and stores the go-webauthn SessionData JSON with a 5-minute TTL. Returns
// the session id the finish call must present.
func (s *Store) CreateWebauthnSession(ctx context.Context, userID uuid.UUID, purpose, dataJSON string) (uuid.UUID, error) {
	var id uuid.UUID
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		// A fresh begin supersedes the user's previous ceremony for this purpose;
		// expired rows (any user) are garbage-collected on the way through.
		if _, err := tx.Exec(ctx,
			`DELETE FROM webauthn_sessions
			  WHERE (user_id = $1 AND purpose = $2) OR expires_at <= now()`,
			userID, purpose); err != nil {
			return fmt.Errorf("prune webauthn sessions: %w", err)
		}

		if err := tx.QueryRow(ctx,
			`INSERT INTO webauthn_sessions (user_id, purpose, data_json, expires_at)
			 VALUES ($1, $2, $3, now() + $4::interval)
			 RETURNING session_id`,
			userID, purpose, dataJSON, webauthnSessionTTL.String()).Scan(&id); err != nil {
			return fmt.Errorf("insert webauthn session: %w", err)
		}
		return nil
	}); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// ConsumeWebauthnSession redeems a challenge session exactly once: the row is
// deleted whether or not the caller's ceremony subsequently verifies, so a
// challenge can never be replayed. Unknown id, wrong user, wrong purpose and
// expired all return ErrNotFound (indistinguishable to the caller). A
// mismatched attempt does NOT burn the session — only an exact match deletes.
func (s *Store) ConsumeWebauthnSession(ctx context.Context, sessionID, userID uuid.UUID, purpose string) (string, error) {
	var (
		dataJSON  string
		expiresAt time.Time
	)
	err := s.pool.QueryRow(ctx,
		`DELETE FROM webauthn_sessions
		  WHERE session_id = $1 AND user_id = $2 AND purpose = $3
		  RETURNING data_json, expires_at`,
		sessionID, userID, purpose).Scan(&dataJSON, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("consume webauthn session: %w", err)
	}
	if !expiresAt.After(time.Now()) {
		// Expired rows are deleted (single-use either way) but not honoured.
		return "", ErrNotFound
	}
	return dataJSON, nil
}

// InsertWebauthnCredential stores a freshly-verified credential and emits the
// enrollment audit event atomically. A credential id that already exists (for
// ANY user — credential ids are globally unique per the WebAuthn spec) is
// ErrConflict.
func (s *Store) InsertWebauthnCredential(ctx context.Context, c WebauthnCredential) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		transports := c.Transports
		if transports == nil {
			transports = []string{}
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_webauthn_credentials
			     (credential_id, user_id, public_key, sign_count, aaguid,
			      transports, backup_eligible, backup_state, label)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			c.CredentialID, c.UserID, c.PublicKey, c.SignCount, c.AAGUID,
			transports, c.BackupEligible, c.BackupState, c.Label); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: credential already registered", ErrConflict)
			}
			return fmt.Errorf("insert webauthn credential: %w", err)
		}
		if err := s.emitAuditTx(ctx, tx, "user.mfa_factor_enrolled", &c.UserID, "",
			&c.UserID, nil, map[string]any{
				"kind":          "passkey",
				"credential_id": c.CredentialID,
				"label":         c.Label,
			}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// ListWebauthnCredentials returns the user's registered passkeys, oldest
// first. An empty slice (no error) when none exist.
func (s *Store) ListWebauthnCredentials(ctx context.Context, userID uuid.UUID) ([]WebauthnCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT credential_id, user_id, public_key, sign_count, aaguid,
		        transports, backup_eligible, backup_state, label,
		        created_at, last_used_at
		   FROM user_webauthn_credentials
		  WHERE user_id = $1
		  ORDER BY created_at, credential_id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list webauthn credentials: %w", err)
	}
	defer rows.Close()

	var out []WebauthnCredential
	for rows.Next() {
		var c WebauthnCredential
		if err := rows.Scan(&c.CredentialID, &c.UserID, &c.PublicKey, &c.SignCount,
			&c.AAGUID, &c.Transports, &c.BackupEligible, &c.BackupState, &c.Label,
			&c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webauthn credentials: %w", err)
	}
	return out, nil
}

// UpdateWebauthnCredentialUsage records a successful assertion: stores the
// new authenticator sign count and stamps last_used_at. The handler MUST have
// verified the assertion (including the sign-count regression check) first.
func (s *Store) UpdateWebauthnCredentialUsage(ctx context.Context, userID uuid.UUID, credentialID string, signCount int64) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE user_webauthn_credentials
		    SET sign_count = $3, last_used_at = now()
		  WHERE credential_id = $1 AND user_id = $2`,
		credentialID, userID, signCount)
	if err != nil {
		return fmt.Errorf("update webauthn credential usage: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RenameWebauthnCredential sets the user-facing label on one of the user's
// passkeys (addressed by credential id) and emits the relabel audit event
// atomically. An empty label clears it back to the client default. Scoped to
// the owner (WHERE user_id) so a caller can only ever relabel their own
// credential; ErrNotFound when the user has no such credential.
func (s *Store) RenameWebauthnCredential(ctx context.Context, userID uuid.UUID, credentialID, label string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE user_webauthn_credentials
			    SET label = $3
			  WHERE credential_id = $1 AND user_id = $2`,
			credentialID, userID, label)
		if err != nil {
			return fmt.Errorf("rename webauthn credential: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.mfa_factor_relabeled", &userID, "",
			&userID, nil, map[string]any{
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

// DeleteWebauthnCredential removes a single passkey and emits the removal
// audit event atomically. ErrNotFound when the user has no such credential.
func (s *Store) DeleteWebauthnCredential(ctx context.Context, userID uuid.UUID, credentialID string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM user_webauthn_credentials
			  WHERE credential_id = $1 AND user_id = $2`, credentialID, userID)
		if err != nil {
			return fmt.Errorf("delete webauthn credential: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.mfa_factor_removed", &userID, "",
			&userID, nil, map[string]any{
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

// DeleteAllWebauthnCredentials removes ALL of the user's passkeys (the
// RemoveFactor kind="passkey" semantics) and emits one removal audit event
// atomically. ErrNotFound when none existed.
func (s *Store) DeleteAllWebauthnCredentials(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM user_webauthn_credentials WHERE user_id = $1`, userID)
		if err != nil {
			return fmt.Errorf("delete webauthn credentials: %w", err)
		}
		n = int(tag.RowsAffected())
		if n == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.mfa_factor_removed", &userID, "",
			&userID, nil, map[string]any{
				"kind":  "passkey",
				"scope": "all",
				"count": n,
			}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return n, nil
}
