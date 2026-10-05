// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MFA second factors, Phase 1: TOTP credentials (user_totp) and transient
// email-OTP challenges (user_email_otp). The TOTP secret arrives here already
// encrypted (handlers own the AES-GCM cipher; the store persists opaque
// blobs). Email codes are stored only as a sha256 hash, same posture as the
// otp_codes subsystem, but keyed by user_id for ALL users (not just local
// accounts) and with MFA-specific TTL/cooldown semantics.

// Email-OTP purposes for the MFA factor. Handlers validate requests against
// this closed set so the purpose column stays a controlled vocabulary.
const (
	// EmailOTPPurposeLogin is the BFF's step-2 login challenge.
	EmailOTPPurposeLogin = "login"
	// EmailOTPPurposeEnroll gates factor-management actions (e.g. proving
	// mailbox control during enrollment flows).
	EmailOTPPurposeEnroll = "enroll"
)

const (
	// emailOTPTTL is the MFA email-code lifetime (5 min per the design spec).
	emailOTPTTL = 5 * time.Minute
	// emailOTPCooldown is the minimum interval between issuing codes for the
	// same (user, purpose); a live code younger than this blocks re-issue.
	emailOTPCooldown = 30 * time.Second
	// emailOTPMaxAttempts mirrors otpMaxAttempts: wrong guesses beyond this
	// consume the code.
	emailOTPMaxAttempts = 5
)

// TotpCredential is a user's TOTP enrollment row. EncryptedSecret is the
// sealed (AES-GCM) shared secret; ConfirmedAt nil = pending enrollment. Label
// is the user-facing name for the factor (empty = show the client default).
type TotpCredential struct {
	UserID          uuid.UUID
	EncryptedSecret string
	ConfirmedAt     *time.Time
	Label           string
	CreatedAt       time.Time
}

// GetTotp returns the user's TOTP credential row (pending or confirmed).
// ErrNotFound when the user has no enrollment.
func (s *Store) GetTotp(ctx context.Context, userID uuid.UUID) (TotpCredential, error) {
	var c TotpCredential
	err := s.pool.QueryRow(ctx,
		`SELECT user_id, encrypted_secret, confirmed_at, label, created_at
		   FROM user_totp WHERE user_id = $1`, userID,
	).Scan(&c.UserID, &c.EncryptedSecret, &c.ConfirmedAt, &c.Label, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TotpCredential{}, ErrNotFound
		}
		return TotpCredential{}, fmt.Errorf("get totp: %w", err)
	}
	return c, nil
}

// RenameTotp sets the user-facing label on the user's TOTP enrollment and
// emits the relabel audit event atomically. An empty label clears it back to
// the client default. Scoped to the owner (WHERE user_id) so a caller can only
// ever touch their own row; ErrNotFound when the user has no enrollment.
func (s *Store) RenameTotp(ctx context.Context, userID uuid.UUID, label string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE user_totp SET label = $2, updated_at = now() WHERE user_id = $1`,
			userID, label)
		if err != nil {
			return fmt.Errorf("rename totp: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.mfa_factor_relabeled", &userID, "",
			&userID, nil, map[string]any{"kind": "totp", "label": label}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// UpsertPendingTotp stores a fresh (already-encrypted) TOTP secret for the
// user with confirmed_at NULL. A pending row is replaced (restarted
// enrollment); a CONFIRMED row is protected — ErrConflict — so an active
// factor can never be silently swapped (RemoveFactor first).
func (s *Store) UpsertPendingTotp(ctx context.Context, userID uuid.UUID, encryptedSecret string) error {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO user_totp (user_id, encrypted_secret)
		 VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE
		    SET encrypted_secret = EXCLUDED.encrypted_secret,
		        confirmed_at     = NULL,
		        updated_at       = now()
		  WHERE user_totp.confirmed_at IS NULL`,
		userID, encryptedSecret)
	if err != nil {
		return fmt.Errorf("upsert pending totp: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: totp already enrolled", ErrConflict)
	}
	return nil
}

// ConfirmTotp activates the user's pending TOTP enrollment (sets
// confirmed_at) and emits the enrollment audit event atomically. The caller
// (handler) MUST have verified a valid code against the pending secret first.
// Idempotent for an already-confirmed row; ErrNotFound when no row exists.
func (s *Store) ConfirmTotp(ctx context.Context, userID uuid.UUID) error {
	return s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var confirmedAt *time.Time
		err := tx.QueryRow(ctx,
			`SELECT confirmed_at FROM user_totp WHERE user_id = $1 FOR UPDATE`,
			userID).Scan(&confirmedAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("select totp: %w", err)
		}
		if confirmedAt != nil {
			// Already active — idempotent success, no duplicate audit event.
			return nil
		}
		if _, err := tx.Exec(ctx,
			`UPDATE user_totp SET confirmed_at = now(), updated_at = now() WHERE user_id = $1`,
			userID); err != nil {
			return fmt.Errorf("confirm totp: %w", err)
		}
		if err := s.emitAuditTx(ctx, tx, "user.mfa_factor_enrolled", &userID, "",
			&userID, nil, map[string]any{"kind": "totp"}); err != nil {
			return err
		}
		return nil
	})
}

// DeleteTotp removes the user's TOTP credential (pending or confirmed) and
// emits the removal audit event atomically. ErrNotFound when nothing existed.
func (s *Store) DeleteTotp(ctx context.Context, userID uuid.UUID) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM user_totp WHERE user_id = $1`, userID)
		if err != nil {
			return fmt.Errorf("delete totp: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.mfa_factor_removed", &userID, "",
			&userID, nil, map[string]any{"kind": "totp"}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// CreateEmailOTP mints a fresh 6-digit MFA code for (userID, purpose), stores
// only its sha256 hash with a 5-minute TTL, and returns the plaintext (to
// email + dev-log) plus the row id (so a failed send can be cancelled). A
// live, unconsumed code younger than the cooldown blocks re-issue with
// ErrOTPRateLimited.
func (s *Store) CreateEmailOTP(ctx context.Context, userID uuid.UUID, purpose string) (string, uuid.UUID, error) {
	var recent int
	var id uuid.UUID
	var code string
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		// Prune dead rows so the table stays small and the cooldown query only
		// ever sees genuinely-live codes.
		if _, err := tx.Exec(ctx,
			`DELETE FROM user_email_otp
			  WHERE user_id = $1 AND purpose = $2
			    AND (consumed_at IS NOT NULL OR expires_at <= now())`,
			userID, purpose); err != nil {
			return fmt.Errorf("prune email otp: %w", err)
		}

		// Cooldown: reject when the newest live code is younger than the window.
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM user_email_otp
			  WHERE user_id = $1 AND purpose = $2
			    AND created_at > now() - $3::interval`,
			userID, purpose, emailOTPCooldown.String()).Scan(&recent); err != nil {
			return fmt.Errorf("cooldown check: %w", err)
		}
		if recent > 0 {
			return ErrOTPRateLimited
		}

		var err error
		code, err = randomNumericCode(otpDigits)
		if err != nil {
			return fmt.Errorf("generate code: %w", err)
		}

		if err := tx.QueryRow(ctx,
			`INSERT INTO user_email_otp (user_id, purpose, code_hash, expires_at)
			 VALUES ($1, $2, $3, now() + $4::interval)
			 RETURNING id`,
			userID, purpose, hashCode(code), emailOTPTTL.String()).Scan(&id); err != nil {
			return fmt.Errorf("insert email otp: %w", err)
		}
		return nil
	}); err != nil {
		return "", uuid.Nil, err
	}
	return code, id, nil
}

// CancelEmailOTP hard-deletes a freshly-minted challenge (used when the email
// send fails, so the failed attempt neither lingers as a live code nor holds
// the re-issue cooldown).
func (s *Store) CancelEmailOTP(ctx context.Context, id uuid.UUID) error {
	if _, err := s.pool.Exec(ctx,
		`DELETE FROM user_email_otp WHERE id = $1`, id); err != nil {
		return fmt.Errorf("cancel email otp: %w", err)
	}
	return nil
}

// VerifyEmailOTP checks a plaintext code against the newest live challenge
// for (userID, purpose). Success consumes the row (single-use). Failures —
// no code / wrong / expired / consumed / attempt-locked — all return
// ErrOTPInvalid (indistinguishable). Wrong guesses bump attempts; hitting the
// limit consumes the code. The hash comparison is constant-time.
func (s *Store) VerifyEmailOTP(ctx context.Context, userID uuid.UUID, purpose, code string) error {
	var outcome error
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		outcome = nil
		var err error

		// Lock the newest candidate row so concurrent verifies serialise on the
		// attempts counter and single-use guarantee.
		var (
			id       uuid.UUID
			stored   string
			attempts int
		)
		err = tx.QueryRow(ctx,
			`SELECT id, code_hash, attempts FROM user_email_otp
		  WHERE user_id = $1 AND purpose = $2
		    AND consumed_at IS NULL AND expires_at > now()
		  ORDER BY created_at DESC
		  LIMIT 1
		  FOR UPDATE`,
			userID, purpose).Scan(&id, &stored, &attempts)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				outcome = ErrOTPInvalid
				return nil
			}
			return fmt.Errorf("select email otp: %w", err)
		}

		if attempts >= emailOTPMaxAttempts {
			// Already locked out; consume defensively and fail.
			if _, err := tx.Exec(ctx,
				`UPDATE user_email_otp SET consumed_at = now() WHERE id = $1`, id); err != nil {
				return fmt.Errorf("consume email otp: %w", err)
			}
			outcome = ErrOTPInvalid
			return nil
		}

		if subtle.ConstantTimeCompare([]byte(hashCode(code)), []byte(stored)) == 1 {
			if _, err := tx.Exec(ctx,
				`UPDATE user_email_otp SET consumed_at = now() WHERE id = $1`, id); err != nil {
				return fmt.Errorf("consume email otp: %w", err)
			}
			return nil
		}

		// Wrong code: bump attempts; consume the row when this hits the limit so
		// a burned code cannot be retried further.
		newAttempts := attempts + 1
		if newAttempts >= emailOTPMaxAttempts {
			_, err = tx.Exec(ctx,
				`UPDATE user_email_otp SET attempts = $2, consumed_at = now() WHERE id = $1`, id, newAttempts)
		} else {
			_, err = tx.Exec(ctx,
				`UPDATE user_email_otp SET attempts = $2 WHERE id = $1`, id, newAttempts)
		}
		if err != nil {
			return fmt.Errorf("bump attempts: %w", err)
		}
		outcome = ErrOTPInvalid
		return nil
	}); err != nil {
		return err
	}
	return outcome
}
