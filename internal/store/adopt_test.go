// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestFindAdoptableLocalUser_ByEmail checks the email-match path.
func TestFindAdoptableLocalUser_ByEmail(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	created, err := s.PreCreateLocalUser(ctx, "adopt-email-user", "adopt@example.org", "Adopt Email")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	// Find by email match (username mismatch shouldn't block the email path).
	u, found, err := s.FindAdoptableLocalUser(ctx, "adopt@example.org", "different-username")
	if err != nil {
		t.Fatalf("FindAdoptableLocalUser: %v", err)
	}
	if !found {
		t.Fatal("expected to find an adoptable local user by email")
	}
	if u.ID != created.ID {
		t.Fatalf("ID mismatch: got %s, want %s", u.ID, created.ID)
	}
	if u.ExternalSubject != "" {
		t.Fatalf("ExternalSubject should be empty, got %q", u.ExternalSubject)
	}
	if !u.LocalAccount {
		t.Fatal("expected LocalAccount=true")
	}
}

// TestFindAdoptableLocalUser_ByUsername checks the username-match fallback path.
func TestFindAdoptableLocalUser_ByUsername(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	created, err := s.PreCreateLocalUser(ctx, "adopt-uname-user", "uniq-other@example.org", "Adopt Username")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	// Find by username match (email mismatch, username matches case-insensitively).
	u, found, err := s.FindAdoptableLocalUser(ctx, "nobody@different.example.org", "ADOPT-UNAME-USER")
	if err != nil {
		t.Fatalf("FindAdoptableLocalUser: %v", err)
	}
	if !found {
		t.Fatal("expected to find adoptable local user by username")
	}
	if u.ID != created.ID {
		t.Fatalf("ID mismatch: got %s, want %s", u.ID, created.ID)
	}
}

// TestFindAdoptableLocalUser_AlreadyAdopted verifies that a row with a
// non-empty external_subject is not returned (already adopted → not adoptable).
func TestFindAdoptableLocalUser_AlreadyAdopted(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// JIT-provision a federated user (has a external_subject, not a local account).
	u, err := s.JITProvision(ctx, "kc-sub-adopted", "federated@example.org", "Federated")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}

	// A JIT user already has external_subject set — not adoptable.
	_, found, err := s.FindAdoptableLocalUser(ctx, u.Email, "")
	if err != nil {
		t.Fatalf("FindAdoptableLocalUser: %v", err)
	}
	if found {
		t.Fatal("JIT-provisioned user (non-empty sub) must not be adoptable")
	}
}

// TestFindAdoptableLocalUser_NoMatch verifies a false result for no match.
func TestFindAdoptableLocalUser_NoMatch(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	_, found, err := s.FindAdoptableLocalUser(ctx, "ghost@example.org", "nobody")
	if err != nil {
		t.Fatalf("FindAdoptableLocalUser: %v", err)
	}
	if found {
		t.Fatal("expected found=false for non-existent user")
	}
}

// TestAdoptLocalUser verifies that AdoptLocalUser sets the external_subject
// on an empty-subject local row and makes it retrievable by subject.
func TestAdoptLocalUser(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	created, err := s.PreCreateLocalUser(ctx, "adopt-kc-user", "kc-adopt@example.org", "KC Adopt")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	if err := s.AdoptLocalUser(ctx, created.ID, "kc-new-subject-abc"); err != nil {
		t.Fatalf("AdoptLocalUser: %v", err)
	}

	// Now the row should be findable by external_subject.
	u, err := s.GetUserByExternalSubject(ctx, "kc-new-subject-abc")
	if err != nil {
		t.Fatalf("GetUserByExternalSubject after adopt: %v", err)
	}
	if u.ID != created.ID {
		t.Fatalf("ID mismatch after adopt: got %s, want %s", u.ID, created.ID)
	}
	if u.ExternalSubject != "kc-new-subject-abc" {
		t.Fatalf("ExternalSubject after adopt: got %q", u.ExternalSubject)
	}
	if !u.LocalAccount {
		t.Fatal("LocalAccount should remain true after adoption")
	}
}

// TestAdoptLocalUser_NotFound verifies ErrNotFound is returned for a bad ID.
func TestAdoptLocalUser_NotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	nonExistent := uuid.New()
	err := s.AdoptLocalUser(ctx, nonExistent, "kc-sub-ghost")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestAdoptLocalUser_AlreadyAdopted verifies ErrConflict is returned when
// the row's external_subject is already set (race / duplicate call). The
// caller (ResolveClaims) uses this signal to fall back to
// GetUserByExternalSubject instead of trusting the stale row ID.
func TestAdoptLocalUser_AlreadyAdopted(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	created, err := s.PreCreateLocalUser(ctx, "double-adopt-user", "double@example.org", "Double Adopt")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	// First adoption succeeds.
	if err := s.AdoptLocalUser(ctx, created.ID, "kc-winner-sub"); err != nil {
		t.Fatalf("first AdoptLocalUser: %v", err)
	}

	// Second adoption (same or different subject) must return ErrConflict.
	err = s.AdoptLocalUser(ctx, created.ID, "kc-loser-sub")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict on already-adopted row, got %v", err)
	}
}
