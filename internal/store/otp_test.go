// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// seedLocalUser creates a local account and returns it.
func seedLocalUser(t *testing.T, s *store.Store, ctx context.Context, username, email string) store.User {
	t.Helper()
	u, err := s.PreCreateLocalUser(ctx, username, email, "Test User")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	return u
}

func TestGenerateAndVerifyOTP_HappyPath(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedLocalUser(t, s, ctx, "otp1", "otp1@example.org")

	code, err := s.GenerateOTP(ctx, u.ID, store.OTPPurposePasswordReset)
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q", code)
	}
	if err := s.VerifyOTP(ctx, u.ID, store.OTPPurposePasswordReset, code); err != nil {
		t.Fatalf("VerifyOTP (good code): %v", err)
	}
	// Single-use: verifying the same code again must fail.
	if err := s.VerifyOTP(ctx, u.ID, store.OTPPurposePasswordReset, code); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("expected ErrOTPInvalid on reuse, got %v", err)
	}
}

func TestVerifyOTP_WrongCodeThenLockout(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedLocalUser(t, s, ctx, "otp2", "otp2@example.org")

	code, err := s.GenerateOTP(ctx, u.ID, store.OTPPurposeLogin2FA)
	if err != nil {
		t.Fatalf("GenerateOTP: %v", err)
	}
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	// Five wrong attempts should lock the code out.
	for i := range 5 {
		if err := s.VerifyOTP(ctx, u.ID, store.OTPPurposeLogin2FA, wrong); !errors.Is(err, store.ErrOTPInvalid) {
			t.Fatalf("attempt %d: expected ErrOTPInvalid, got %v", i, err)
		}
	}
	// Even the CORRECT code now fails — the row was consumed at lockout.
	if err := s.VerifyOTP(ctx, u.ID, store.OTPPurposeLogin2FA, code); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("expected lockout to reject correct code, got %v", err)
	}
}

func TestVerifyOTP_NoCode(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedLocalUser(t, s, ctx, "otp3", "otp3@example.org")

	if err := s.VerifyOTP(ctx, u.ID, store.OTPPurposePasswordReset, "123456"); !errors.Is(err, store.ErrOTPInvalid) {
		t.Fatalf("expected ErrOTPInvalid when no code exists, got %v", err)
	}
}

func TestGenerateOTP_RateLimit(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedLocalUser(t, s, ctx, "otp4", "otp4@example.org")

	// Cap is 3 active codes per (user, purpose).
	for i := range 3 {
		if _, err := s.GenerateOTP(ctx, u.ID, store.OTPPurposePasswordReset); err != nil {
			t.Fatalf("GenerateOTP %d: %v", i, err)
		}
	}
	if _, err := s.GenerateOTP(ctx, u.ID, store.OTPPurposePasswordReset); !errors.Is(err, store.ErrOTPRateLimited) {
		t.Fatalf("expected ErrOTPRateLimited on 4th active code, got %v", err)
	}
	// A different purpose has its own budget.
	if _, err := s.GenerateOTP(ctx, u.ID, store.OTPPurposeLogin2FA); err != nil {
		t.Fatalf("GenerateOTP (other purpose): %v", err)
	}
}

func TestGetLocalUserByEmail(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedLocalUser(t, s, ctx, "otp5", "OTP5@Example.org")

	got, err := s.GetLocalUserByEmail(ctx, "otp5@example.org") // case-insensitive
	if err != nil {
		t.Fatalf("GetLocalUserByEmail: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("got id %s, want %s", got.ID, u.ID)
	}
	if _, err := s.GetLocalUserByEmail(ctx, "nobody@example.org"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown email, got %v", err)
	}
}
