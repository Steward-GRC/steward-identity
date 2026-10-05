// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestJITProvisionDerivesUsernameAndLeavesUnonboarded verifies a fresh JIT user
// starts un-onboarded (needs_onboarding=true) and gets a username derived from
// the email local-part.
func TestJITProvisionDerivesUsernameAndLeavesUnonboarded(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "onb-sub-1", "alice@example.org", "Alice")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}
	if u.OnboardingComplete {
		t.Fatal("new JIT user must start onboarding_complete=false")
	}
	if u.Username != "alice" {
		t.Fatalf("derived username: got %q want %q", u.Username, "alice")
	}
}

// TestJITProvisionUsernameCollisionSuffixes verifies a second JIT user whose
// email local-part collides gets a numeric suffix.
func TestJITProvisionUsernameCollisionSuffixes(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	if _, err := s.JITProvision(ctx, "col-1", "jdoe@a.example.org", "J Doe A"); err != nil {
		t.Fatalf("first JIT: %v", err)
	}
	u2, err := s.JITProvision(ctx, "col-2", "jdoe@b.example.org", "J Doe B")
	if err != nil {
		t.Fatalf("second JIT: %v", err)
	}
	if u2.Username != "jdoe2" {
		t.Fatalf("second derived username: got %q want %q", u2.Username, "jdoe2")
	}
}

// TestAdoptLeavesUserOnboarded verifies the adopt-by-precreated path marks the
// (already-existing) user onboarded.
func TestAdoptLeavesUserOnboarded(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	pre, err := s.PreCreateLocalUser(ctx, "carol", "carol@example.org", "Carol")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	// A pre-created local row is not yet onboarded.
	if pre.OnboardingComplete {
		t.Fatal("pre-created local user should start onboarding_complete=false")
	}
	if err := s.AdoptLocalUser(ctx, pre.ID, "adopt-sub-1"); err != nil {
		t.Fatalf("AdoptLocalUser: %v", err)
	}
	got, err := s.GetUser(ctx, pre.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !got.OnboardingComplete {
		t.Fatal("adopted user must end up onboarding_complete=true")
	}
	if got.Username != "carol" {
		t.Fatalf("adopted user username changed: got %q", got.Username)
	}
}

// TestCompleteOnboarding verifies the flag flips, terms are stamped once, and a
// provided name/username are applied.
func TestCompleteOnboarding(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "cmp-sub-1", "dave@example.org", "Dave")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}

	done, err := s.CompleteOnboarding(ctx, u.ID)
	if err != nil {
		t.Fatalf("CompleteOnboarding: %v", err)
	}
	if !done.OnboardingComplete {
		t.Fatal("expected onboarding_complete=true")
	}

	var terms1 *time.Time
	if err := pool.QueryRow(ctx, `SELECT terms_accepted_at FROM users WHERE id=$1`, u.ID).Scan(&terms1); err != nil {
		t.Fatalf("read terms_accepted_at: %v", err)
	}
	if terms1 == nil {
		t.Fatal("expected terms_accepted_at to be stamped")
	}

	// Re-completing keeps the original acceptance timestamp (COALESCE).
	if _, err := s.CompleteOnboarding(ctx, u.ID); err != nil {
		t.Fatalf("second CompleteOnboarding: %v", err)
	}
	var terms2 *time.Time
	if err := pool.QueryRow(ctx, `SELECT terms_accepted_at FROM users WHERE id=$1`, u.ID).Scan(&terms2); err != nil {
		t.Fatalf("read terms_accepted_at 2: %v", err)
	}
	if terms2 == nil || !terms2.Equal(*terms1) {
		t.Fatalf("terms_accepted_at must be stable across re-completion: %v vs %v", terms1, terms2)
	}
}

// TestUpdateUsernameConflict verifies a duplicate username is rejected as a
// conflict.
func TestUpdateUsernameConflict(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	a, err := s.JITProvision(ctx, "uc-1", "erin@a.example.org", "Erin")
	if err != nil {
		t.Fatalf("JIT a: %v", err)
	}
	if _, err := s.JITProvision(ctx, "uc-2", "frank@b.example.org", "Frank"); err != nil {
		t.Fatalf("JIT b: %v", err)
	}

	// erin -> "frank" collides with the second user (case-insensitive).
	_, err = s.UpdateUsername(ctx, a.ID, "Frank")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	// A free username succeeds.
	got, err := s.UpdateUsername(ctx, a.ID, "erin-new")
	if err != nil {
		t.Fatalf("UpdateUsername free: %v", err)
	}
	if got.Username != "erin-new" {
		t.Fatalf("username: got %q", got.Username)
	}

	// Unknown id -> not found.
	if _, err := s.UpdateUsername(ctx, uuid.New(), "whatever"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
