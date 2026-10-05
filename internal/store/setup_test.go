// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
)

func TestHasRootUser(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// Fresh DB: no root user.
	has, err := s.HasRootUser(ctx)
	if err != nil {
		t.Fatalf("HasRootUser: %v", err)
	}
	if has {
		t.Fatal("expected HasRootUser=false on fresh DB")
	}

	// Insert a root user via PreCreateLocalUserRoot.
	_, err = s.PreCreateLocalUserRoot(ctx, "rootuser", "root@example.org", "Test Root")
	if err != nil {
		t.Fatalf("PreCreateLocalUserRoot: %v", err)
	}

	has, err = s.HasRootUser(ctx)
	if err != nil {
		t.Fatalf("HasRootUser after insert: %v", err)
	}
	if !has {
		t.Fatal("expected HasRootUser=true after inserting root user")
	}
}

func TestPreCreateLocalUserRoot_SetsIsRoot(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.PreCreateLocalUserRoot(ctx, "rootuser2", "root2@example.org", "Test Root")
	if err != nil {
		t.Fatalf("PreCreateLocalUserRoot: %v", err)
	}
	if !u.IsRoot {
		t.Fatal("expected is_root=true on returned user")
	}
	if !u.LocalAccount {
		t.Fatal("expected local_account=true")
	}
	if u.Email != "root2@example.org" {
		t.Fatalf("email: got %q", u.Email)
	}
	if u.Username != "rootuser2" {
		t.Fatalf("username: got %q", u.Username)
	}
}

func TestPreCreateLocalUserRoot_Conflict(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	if _, err := s.PreCreateLocalUserRoot(ctx, "rootdup", "rd@example.org", "Test Root"); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := s.PreCreateLocalUserRoot(ctx, "rootdup", "rd2@example.org", "Test Root")
	if err == nil {
		t.Fatal("expected error on duplicate username")
	}
}
