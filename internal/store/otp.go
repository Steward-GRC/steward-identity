// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Steward-GRC/steward-identity/internal/safecast"
)

// OTP subsystem for LOCAL accounts: numeric one-time codes for password reset
// and local-login 2FA. Codes are stored only as a sha256 hash; the plaintext is
// returned once to the caller (to email + dev-log) and never persisted.

// OTP purposes. Kept as constants so callers and the schema stay in lockstep.
const (
	OTPPurposePasswordReset = "password_reset"
	OTPPurposeLogin2FA      = "login_2fa"
	// OTPPurposeStepUp gates high-risk authenticated admin actions (e.g.
	// TransferRoot) with an emailed one-time code the backend verifies for the
	// acting admin before executing.
	OTPPurposeStepUp = "step_up"
)

const (
	// otpTTL is the code lifetime. Short, per the spec (10 min).
	otpTTL = 10 * time.Minute
	// otpMaxAttempts is the failed-verify lockout threshold. After this many
	// wrong guesses the code is consumed (dead) even if never matched.
	otpMaxAttempts = 5
	// otpMaxActivePerUser caps concurrently-live codes per (user, purpose) to
	// bound request-side flooding. Older active codes beyond this are pruned.
	otpMaxActivePerUser = 3
	// otpDigits is the numeric code length.
	otpDigits = 6
)

// OTP-specific sentinel errors. Handlers map these to gRPC codes.
var (
	// ErrOTPInvalid covers "no matching code", "wrong code", "expired",
	// "already used", and "too many attempts" — deliberately indistinguishable
	// so a verify call leaks nothing beyond pass/fail.
	ErrOTPInvalid = errors.New("invalid or expired code")
	// ErrOTPRateLimited is returned by GenerateOTP when the active-code cap is
	// exceeded and no slot can be reclaimed.
	ErrOTPRateLimited = errors.New("too many active codes")
)

// GetLocalUserByEmail returns the LOCAL (local_account=true) user matching the
// given email (case-insensitive). SSO rows are excluded so the OTP flows only
// ever operate on local passwords. Returns
// ErrNotFound if no such local user exists.
//
// TOMBSTONED rows are excluded: this resolves the principal a
// password-reset or login-2FA code is minted for and verified against, so a
// deleted account matching here means an emailed OTP for an account that no
// longer exists. The `ORDER BY created_at ASC` tie-break made it worse — the
// tombstone is normally the OLDER row, so with a duplicate-email pair the
// deleted account was preferred over the live one.
func (s *Store) GetLocalUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	var un *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, first_name, last_name
		 FROM users WHERE lower(email) = lower($1) AND local_account = true AND deleted_at IS NULL
		 ORDER BY created_at ASC LIMIT 1`, email,
	).Scan(&u.ID, &u.ExternalSubject, &un, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.FirstName, &u.LastName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get local user by email: %w", err)
	}
	if un != nil {
		u.Username = *un
	}
	if err := s.hydrateUser(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// GenerateOTP mints a fresh numeric code for (userID, purpose), stores only its
// sha256 hash with a short TTL, and returns the plaintext for the caller to
// email + dev-log. It enforces a per-(user,purpose) active-code cap: it first
// prunes expired/consumed rows, then rejects with ErrOTPRateLimited if the live
// count is still at the cap.
func (s *Store) GenerateOTP(ctx context.Context, userID uuid.UUID, purpose string) (string, error) {
	var active int
	var code string
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		// Prune dead rows (expired or consumed) for this (user, purpose) so the
		// active count reflects only genuinely-live codes.
		if _, err := tx.Exec(ctx,
			`DELETE FROM otp_codes
			  WHERE user_id = $1 AND purpose = $2
			    AND (consumed_at IS NOT NULL OR expires_at <= now())`,
			userID, purpose); err != nil {
			return fmt.Errorf("prune otp: %w", err)
		}

		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM otp_codes WHERE user_id = $1 AND purpose = $2`,
			userID, purpose).Scan(&active); err != nil {
			return fmt.Errorf("count active otp: %w", err)
		}
		if active >= otpMaxActivePerUser {
			return ErrOTPRateLimited
		}

		var err error
		code, err = randomNumericCode(otpDigits)
		if err != nil {
			return fmt.Errorf("generate code: %w", err)
		}
		hash := hashCode(code)

		if _, err := tx.Exec(ctx,
			`INSERT INTO otp_codes (user_id, purpose, code_hash, expires_at)
			 VALUES ($1, $2, $3, now() + $4::interval)`,
			userID, purpose, hash, fmt.Sprintf("%d seconds", int(otpTTL.Seconds()))); err != nil {
			return fmt.Errorf("insert otp: %w", err)
		}

		return nil
	}); err != nil {
		return "", err
	}
	return code, nil
}

// VerifyOTP checks a plaintext code against the newest live code for
// (userID, purpose). On success it marks the row consumed and returns nil. On
// any failure (no code / wrong / expired / used / attempt-limit) it returns
// ErrOTPInvalid; wrong guesses increment attempts and the row is consumed once
// the attempt limit is hit. The hash comparison is constant-time.
func (s *Store) VerifyOTP(ctx context.Context, userID uuid.UUID, purpose, code string) error {
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
			`SELECT id, code_hash, attempts FROM otp_codes
		  WHERE user_id = $1 AND purpose = $2
		    AND consumed_at IS NULL AND expires_at > now()
		  ORDER BY created_at DESC
		  LIMIT 1
		  FOR UPDATE`,
			userID, purpose).Scan(&id, &stored, &attempts)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				// No live code at all — indistinguishable failure.
				outcome = ErrOTPInvalid
				return nil
			}
			return fmt.Errorf("select otp: %w", err)
		}

		if attempts >= otpMaxAttempts {
			// Already locked out; consume it defensively and fail.
			if _, err := tx.Exec(ctx, `UPDATE otp_codes SET consumed_at = now() WHERE id = $1`, id); err != nil {
				return fmt.Errorf("consume otp: %w", err)
			}
			outcome = ErrOTPInvalid
			return nil
		}

		if subtle.ConstantTimeCompare([]byte(hashCode(code)), []byte(stored)) == 1 {
			if _, err := tx.Exec(ctx, `UPDATE otp_codes SET consumed_at = now() WHERE id = $1`, id); err != nil {
				return fmt.Errorf("consume otp: %w", err)
			}
			return nil
		}

		// Wrong code: bump attempts, and consume the row if this pushed us to the
		// lockout threshold so a burned code can't be retried further.
		newAttempts := attempts + 1
		if newAttempts >= otpMaxAttempts {
			_, err = tx.Exec(ctx, `UPDATE otp_codes SET attempts = $2, consumed_at = now() WHERE id = $1`, id, newAttempts)
		} else {
			_, err = tx.Exec(ctx, `UPDATE otp_codes SET attempts = $2 WHERE id = $1`, id, newAttempts)
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

// hashCode returns the hex sha256 of a plaintext code (what we store at rest).
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// randomNumericCode returns an n-digit numeric string using crypto/rand, with
// leading zeros preserved (so a 6-digit code is always exactly 6 chars).
func randomNumericCode(n int) (string, error) {
	buf := make([]byte, n)
	for i := range n {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		buf[i] = safecast.ByteFromInt64('0' + d.Int64())
	}
	return string(buf), nil
}
