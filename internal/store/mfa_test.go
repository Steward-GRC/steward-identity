// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// seedMfaUser creates a user (JIT path — MFA applies to ALL users, not just
// local accounts) and returns it.
func seedMfaUser(t *testing.T, s *store.Store, ctx context.Context, sub, email string) store.User {
	t.Helper()
	u, err := s.JITProvision(ctx, sub, email, "MFA Test User")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}
	return u
}

// --- TOTP credential rows ---

func TestTotpUpsertGetConfirmLifecycle(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-totp-1", "totp1@example.org")

	// No enrollment yet.
	if _, err := s.GetTotp(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetTotp on empty: want ErrNotFound, got %v", err)
	}

	// Begin: pending (unconfirmed) row.
	if err := s.UpsertPendingTotp(ctx, u.ID, "sealed-v1"); err != nil {
		t.Fatalf("UpsertPendingTotp: %v", err)
	}
	cred, err := s.GetTotp(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTotp: %v", err)
	}
	if cred.EncryptedSecret != "sealed-v1" || cred.ConfirmedAt != nil {
		t.Fatalf("pending cred wrong: %+v", cred)
	}

	// Re-begin before confirm replaces the pending secret.
	if err := s.UpsertPendingTotp(ctx, u.ID, "sealed-v2"); err != nil {
		t.Fatalf("UpsertPendingTotp (replace pending): %v", err)
	}
	cred, err = s.GetTotp(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTotp: %v", err)
	}
	if cred.EncryptedSecret != "sealed-v2" || cred.ConfirmedAt != nil {
		t.Fatalf("replaced pending cred wrong: %+v", cred)
	}

	// Confirm activates it.
	if err := s.ConfirmTotp(ctx, u.ID); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
	cred, err = s.GetTotp(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTotp: %v", err)
	}
	if cred.ConfirmedAt == nil {
		t.Fatal("ConfirmTotp did not set confirmed_at")
	}

	// A confirmed enrollment cannot be silently replaced.
	if err := s.UpsertPendingTotp(ctx, u.ID, "sealed-v3"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("UpsertPendingTotp over confirmed: want ErrConflict, got %v", err)
	}
	cred, _ = s.GetTotp(ctx, u.ID)
	if cred.EncryptedSecret != "sealed-v2" {
		t.Fatalf("confirmed secret was overwritten: %+v", cred)
	}

	// Delete clears it; second delete reports not found.
	if err := s.DeleteTotp(ctx, u.ID); err != nil {
		t.Fatalf("DeleteTotp: %v", err)
	}
	if _, err := s.GetTotp(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetTotp after delete: want ErrNotFound, got %v", err)
	}
	if err := s.DeleteTotp(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DeleteTotp on empty: want ErrNotFound, got %v", err)
	}
}

func TestConfirmTotpWithoutPendingRow(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-totp-2", "totp2@example.org")

	if err := s.ConfirmTotp(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ConfirmTotp with no row: want ErrNotFound, got %v", err)
	}
	// Idempotent once confirmed.
	if err := s.UpsertPendingTotp(ctx, u.ID, "sealed"); err != nil {
		t.Fatalf("UpsertPendingTotp: %v", err)
	}
	if err := s.ConfirmTotp(ctx, u.ID); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
	if err := s.ConfirmTotp(ctx, u.ID); err != nil {
		t.Fatalf("ConfirmTotp (repeat): %v", err)
	}
}

// --- Email OTP challenges ---

func TestEmailOTPHappyPathAndSingleUse(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-eotp-1", "eotp1@example.org")

	code, _, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin)
	if err != nil {
		t.Fatalf("CreateEmailOTP: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("want 6-digit code, got %q", code)
	}
	// Wrong purpose does not verify.
	if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeEnroll, code); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("verify with wrong purpose: want ErrOTPInvalid, got %v", err)
	}
	if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin, code); err != nil {
		t.Fatalf("VerifyEmailOTP (good): %v", err)
	}
	// Single-use.
	if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin, code); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("reuse: want ErrOTPInvalid, got %v", err)
	}
}

func TestEmailOTPWrongCodeThenLockout(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-eotp-2", "eotp2@example.org")

	code, _, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin)
	if err != nil {
		t.Fatalf("CreateEmailOTP: %v", err)
	}
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	for i := range 5 {
		if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin, wrong); !errors.Is(err, store.ErrOTPInvalid) {
			t.Fatalf("attempt %d: want ErrOTPInvalid, got %v", i, err)
		}
	}
	// Locked out: even the correct code fails now.
	if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin, code); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("post-lockout correct code: want ErrOTPInvalid, got %v", err)
	}
}

func TestEmailOTPExpires(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-eotp-3", "eotp3@example.org")

	code, id, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin)
	if err != nil {
		t.Fatalf("CreateEmailOTP: %v", err)
	}
	// TTL is 5 minutes.
	var ttl time.Duration
	if err := pool.QueryRow(ctx,
		`SELECT expires_at - created_at FROM user_email_otp WHERE id = $1`, id).Scan(&ttl); err != nil {
		t.Fatalf("read ttl: %v", err)
	}
	if ttl != 5*time.Minute {
		t.Fatalf("want 5m TTL, got %v", ttl)
	}
	// Backdate to expired.
	backdate(t, pool, id, 6*time.Minute)
	if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin, code); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("expired code: want ErrOTPInvalid, got %v", err)
	}
}

func TestEmailOTPReissueCooldown(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-eotp-4", "eotp4@example.org")

	_, id, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin)
	if err != nil {
		t.Fatalf("CreateEmailOTP: %v", err)
	}
	// Immediate re-issue is rate-limited.
	if _, _, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin); !errors.Is(err, store.ErrOTPRateLimited) {
		t.Fatalf("re-issue in cooldown: want ErrOTPRateLimited, got %v", err)
	}
	// A different purpose is an independent challenge stream.
	if _, _, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeEnroll); err != nil {
		t.Fatalf("re-issue different purpose: %v", err)
	}
	// Once the cooldown has elapsed a new code can be minted (and it
	// supersedes the old one for verification, newest-first).
	backdate(t, pool, id, 31*time.Second)
	code2, _, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin)
	if err != nil {
		t.Fatalf("re-issue after cooldown: %v", err)
	}
	if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin, code2); err != nil {
		t.Fatalf("verify newest code: %v", err)
	}
}

func TestEmailOTPCancel(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-eotp-5", "eotp5@example.org")

	code, id, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin)
	if err != nil {
		t.Fatalf("CreateEmailOTP: %v", err)
	}
	if err := s.CancelEmailOTP(ctx, id); err != nil {
		t.Fatalf("CancelEmailOTP: %v", err)
	}
	// Cancelled code cannot verify…
	if err := s.VerifyEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin, code); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("cancelled code: want ErrOTPInvalid, got %v", err)
	}
	// …and does not hold the cooldown (send failure must not lock the user out).
	if _, _, err := s.CreateEmailOTP(ctx, u.ID, store.EmailOTPPurposeLogin); err != nil {
		t.Fatalf("re-issue after cancel: %v", err)
	}
}

// backdate shifts a user_email_otp row's created_at/expires_at into the past
// by d, so expiry/cooldown behavior is testable without sleeping.
func backdate(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, d time.Duration) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE user_email_otp
		    SET created_at = created_at - $2::interval,
		        expires_at = expires_at - $2::interval
		  WHERE id = $1`, id, d.String()); err != nil {
		t.Fatalf("backdate: %v", err)
	}
}
