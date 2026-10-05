// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// --- TOTP factor label ---

func TestRenameTotpLabel(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-totp-label-1", "totplabel1@example.org")

	// No enrollment yet → rename is a no-op miss.
	if err := s.RenameTotp(ctx, u.ID, "Authenticator app"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RenameTotp with no enrollment: want ErrNotFound, got %v", err)
	}

	// Enroll (default label is empty).
	if err := s.UpsertPendingTotp(ctx, u.ID, "sealed"); err != nil {
		t.Fatalf("UpsertPendingTotp: %v", err)
	}
	if err := s.ConfirmTotp(ctx, u.ID); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
	cred, err := s.GetTotp(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTotp: %v", err)
	}
	if cred.Label != "" {
		t.Fatalf("fresh enrollment should have empty label, got %q", cred.Label)
	}

	// Rename sets and returns the label.
	if err := s.RenameTotp(ctx, u.ID, "Authenticator app"); err != nil {
		t.Fatalf("RenameTotp: %v", err)
	}
	cred, err = s.GetTotp(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTotp: %v", err)
	}
	if cred.Label != "Authenticator app" {
		t.Fatalf("want label 'Authenticator app', got %q", cred.Label)
	}

	// Empty label clears it back to the default.
	if err := s.RenameTotp(ctx, u.ID, ""); err != nil {
		t.Fatalf("RenameTotp (clear): %v", err)
	}
	if cred, _ = s.GetTotp(ctx, u.ID); cred.Label != "" {
		t.Fatalf("clear label: want empty, got %q", cred.Label)
	}
}

// A user renaming their own TOTP factor never touches another user's row —
// the row is the caller's own (WHERE user_id / user_totp PK).
func TestRenameTotpLabelIsolatedPerUser(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	a := seedMfaUser(t, s, ctx, "kc-totp-label-a", "totplabela@example.org")
	b := seedMfaUser(t, s, ctx, "kc-totp-label-b", "totplabelb@example.org")

	// Both enroll.
	if err := s.UpsertPendingTotp(ctx, a.ID, "sealed-a"); err != nil {
		t.Fatalf("enroll a: %v", err)
	}
	if err := s.ConfirmTotp(ctx, a.ID); err != nil {
		t.Fatalf("confirm a: %v", err)
	}
	if err := s.UpsertPendingTotp(ctx, b.ID, "sealed-b"); err != nil {
		t.Fatalf("enroll b: %v", err)
	}
	if err := s.ConfirmTotp(ctx, b.ID); err != nil {
		t.Fatalf("confirm b: %v", err)
	}

	if err := s.RenameTotp(ctx, a.ID, "A phone"); err != nil {
		t.Fatalf("RenameTotp a: %v", err)
	}
	// B is untouched.
	credB, err := s.GetTotp(ctx, b.ID)
	if err != nil {
		t.Fatalf("GetTotp b: %v", err)
	}
	if credB.Label != "" {
		t.Fatalf("renaming A leaked into B's label: %q", credB.Label)
	}
}

// --- Passkey (WebAuthn) credential label ---

func TestRenameWebauthnCredentialLabel(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u := seedMfaUser(t, s, ctx, "kc-wa-label-1", "walabel1@example.org")
	other := seedMfaUser(t, s, ctx, "kc-wa-label-2", "walabel2@example.org")

	if err := s.InsertWebauthnCredential(ctx, testCred(u.ID, "cred-lbl")); err != nil {
		t.Fatalf("InsertWebauthnCredential: %v", err)
	}

	// Unknown credential id → miss.
	if err := s.RenameWebauthnCredential(ctx, u.ID, "no-such", "x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rename unknown: want ErrNotFound, got %v", err)
	}

	// Rename sets and is returned by the list path.
	if err := s.RenameWebauthnCredential(ctx, u.ID, "cred-lbl", "1Password"); err != nil {
		t.Fatalf("RenameWebauthnCredential: %v", err)
	}
	list, err := s.ListWebauthnCredentials(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListWebauthnCredentials: err=%v len=%d", err, len(list))
	}
	if list[0].Label != "1Password" {
		t.Fatalf("want label '1Password', got %q", list[0].Label)
	}

	// A DIFFERENT user cannot relabel this credential (WHERE user_id scoping):
	// the write misses, and the owner's label is unchanged.
	if err := s.RenameWebauthnCredential(ctx, other.ID, "cred-lbl", "hacked"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-user rename: want ErrNotFound, got %v", err)
	}
	list, _ = s.ListWebauthnCredentials(ctx, u.ID)
	if list[0].Label != "1Password" {
		t.Fatalf("cross-user rename leaked: label now %q", list[0].Label)
	}

	// Empty label clears it.
	if err := s.RenameWebauthnCredential(ctx, u.ID, "cred-lbl", ""); err != nil {
		t.Fatalf("RenameWebauthnCredential (clear): %v", err)
	}
	list, _ = s.ListWebauthnCredentials(ctx, u.ID)
	if list[0].Label != "" {
		t.Fatalf("clear label: want empty, got %q", list[0].Label)
	}
}
