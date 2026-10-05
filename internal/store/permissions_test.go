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

func TestGrantPermission_ReadSensitive(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-perm-grant", "perm@e", "Perm")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	if err := s.GrantPermission(ctx, u.ID, "policy.read_sensitive", nil, "root"); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !got.ReadSensitive {
		t.Fatal("expected ReadSensitive true after grant")
	}

	// Idempotent.
	if err := s.GrantPermission(ctx, u.ID, "policy.read_sensitive", nil, "root"); err != nil {
		t.Fatalf("GrantPermission (again): %v", err)
	}
}

func TestRevokePermission_ReadSensitive(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-perm-revoke", "permr@e", "PermR")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	if err := s.GrantPermission(ctx, u.ID, "policy.read_sensitive", nil, "root"); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	if err := s.RevokePermission(ctx, u.ID, "policy.read_sensitive", nil, "root"); err != nil {
		t.Fatalf("RevokePermission: %v", err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.ReadSensitive {
		t.Fatal("expected ReadSensitive false after revoke")
	}
}

func TestGrantPermission_Invalid(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-perm-inv", "permi@e", "PermI")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	if err := s.GrantPermission(ctx, u.ID, "bogus.permission", nil, "root"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for unknown permission, got %v", err)
	}
}

func TestGrantPermission_UserNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	if err := s.GrantPermission(context.Background(), uuid.New(), "policy.read_sensitive", nil, "root"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
