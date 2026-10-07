// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

func contains(s []string, v string) bool {
	return slices.Contains(s, v)
}

// TestRootProtection covers the root guards: a user flagged is_root cannot be
// disabled or stripped of site-admin, GetUser surfaces the flag, and
// GrantRoot adds a root admin (granting site-admin) and RevokeRoot removes
// one, after which the former root is unprotected.
func TestRootProtection(t *testing.T) {
	pool := newTestDB(t)
	s := newStoreFor(t, pool)
	ctx := context.Background()

	root, err := s.JITProvision(ctx, "root-sub", "root@test.example.org", "Root")
	if err != nil {
		t.Fatalf("provision root: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET is_root = true WHERE id = $1`, root.ID); err != nil {
		t.Fatalf("mark root: %v", err)
	}
	if _, err := s.GrantRole(ctx, root.ID, "site-admin", "", nil, ""); err != nil {
		t.Fatalf("grant site-admin: %v", err)
	}

	got, err := s.GetUser(ctx, root.ID)
	if err != nil {
		t.Fatalf("get root: %v", err)
	}
	if !got.IsRoot {
		t.Fatal("GetUser did not surface IsRoot")
	}

	// Cannot disable the root.
	if _, err := s.SetEnabled(ctx, root.ID, false, nil, ""); !errors.Is(err, store.ErrRootProtected) {
		t.Fatalf("disable root: want ErrRootProtected, got %v", err)
	}
	// Cannot strip the root's site-admin.
	if _, err := s.RevokeRole(ctx, root.ID, "site-admin", "", nil, ""); !errors.Is(err, store.ErrRootProtected) {
		t.Fatalf("revoke root site-admin: want ErrRootProtected, got %v", err)
	}

	// Grant root to a second user, then revoke it from the first.
	other, err := s.JITProvision(ctx, "other-sub", "other@test.example.org", "Other")
	if err != nil {
		t.Fatalf("provision other: %v", err)
	}
	granted, err := s.GrantRoot(ctx, other.ID, nil, "")
	if err != nil {
		t.Fatalf("grant root: %v", err)
	}
	if !granted.IsRoot {
		t.Fatal("grant target is not root")
	}
	if !contains(granted.Roles, "site-admin") {
		t.Fatalf("grant target missing site-admin role: %v", granted.Roles)
	}
	if contains(granted.Roles, "admin") {
		t.Fatalf("grant target must not get dropped role 'admin': %v", granted.Roles)
	}
	if _, err := s.RevokeRoot(ctx, root.ID, nil, ""); err != nil {
		t.Fatalf("revoke root: %v", err)
	}

	// The former root is no longer root and is now disable-able.
	oldRoot, err := s.GetUser(ctx, root.ID)
	if err != nil {
		t.Fatalf("get old root: %v", err)
	}
	if oldRoot.IsRoot {
		t.Fatal("old root still flagged is_root after revoke")
	}
	if !contains(oldRoot.Roles, "site-admin") {
		t.Fatalf("revoking root keeps site-admin: %v", oldRoot.Roles)
	}
	if _, err := s.SetEnabled(ctx, root.ID, false, nil, ""); err != nil {
		t.Fatalf("disable former root: %v", err)
	}
}
