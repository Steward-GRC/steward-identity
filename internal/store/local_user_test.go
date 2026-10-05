// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

func TestPreCreateLocalUser(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.PreCreateLocalUser(ctx, "jdoe", "jdoe@example.org", "John Doe")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	if u.ID.String() == "" {
		t.Fatal("expected non-empty ID")
	}
	if u.Username != "jdoe" {
		t.Fatalf("Username: got %q, want %q", u.Username, "jdoe")
	}
	if u.Email != "jdoe@example.org" {
		t.Fatalf("Email: got %q", u.Email)
	}
	if !u.LocalAccount {
		t.Fatal("expected LocalAccount=true")
	}
	if u.ExternalSubject != "" {
		t.Fatalf("ExternalSubject should be empty for pre-created user, got %q", u.ExternalSubject)
	}
	if !u.Enabled {
		t.Fatal("expected Enabled=true")
	}

	// Audit: user.created emitted
	n, err := s.CountAuditPending(ctx)
	if err != nil {
		t.Fatalf("CountAuditPending: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 audit event, got %d", n)
	}
}

func TestPreCreateLocalUser_DuplicateUsernameConflict(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	if _, err := s.PreCreateLocalUser(ctx, "alice", "alice@example.org", "Alice"); err != nil {
		t.Fatalf("first PreCreateLocalUser: %v", err)
	}
	// Second call with same username (case-insensitive) must return ErrConflict.
	_, err := s.PreCreateLocalUser(ctx, "ALICE", "alice2@example.org", "Alice2")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict for duplicate username, got %v", err)
	}
}

func TestGetUserByUsername(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	created, err := s.PreCreateLocalUser(ctx, "treader", "treader@example.org", "Test Reader")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	got, err := s.GetUserByUsername(ctx, "TREADER") // case-insensitive lookup
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("ID mismatch: got %s, want %s", got.ID, created.ID)
	}
	if got.Username != "treader" {
		t.Fatalf("Username: got %q", got.Username)
	}
}

func TestGetUserByUsername_NotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	_, err := s.GetUserByUsername(ctx, "nobody")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
