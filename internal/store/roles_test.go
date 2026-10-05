// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

func containsScopedRole(sr []store.ScopedRole, role, cat string) bool {
	for _, r := range sr {
		if r.Role == role && r.Category == cat {
			return true
		}
	}
	return false
}

func countScopedRole(sr []store.ScopedRole, role, cat string) int {
	n := 0
	for _, r := range sr {
		if r.Role == role && r.Category == cat {
			n++
		}
	}
	return n
}

func TestGrantAndRevokeRole(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-grant", "g@e", "G")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	// author is a scoped role — requires a non-empty category; lands in ScopedRoles.
	u, err = s.GrantRole(ctx, u.ID, "author", "Facilities", nil, "tester")
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if !containsScopedRole(u.ScopedRoles, "author", "Facilities") {
		t.Fatalf("expected author/Facilities in ScopedRoles, got %v", u.ScopedRoles)
	}

	// Idempotent.
	u, err = s.GrantRole(ctx, u.ID, "author", "Facilities", nil, "tester")
	if err != nil {
		t.Fatalf("GrantRole (again): %v", err)
	}
	if countScopedRole(u.ScopedRoles, "author", "Facilities") != 1 {
		t.Fatalf("expected single author/Facilities entry, got %v", u.ScopedRoles)
	}

	u, err = s.RevokeRole(ctx, u.ID, "author", "Facilities", nil, "tester")
	if err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	if containsScopedRole(u.ScopedRoles, "author", "Facilities") {
		t.Fatalf("expected author absent, got %v", u.ScopedRoles)
	}
}

func TestGrantRoleInvalid(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-inv", "x@e", "X")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	_, err = s.GrantRole(ctx, u.ID, "badrole", "", nil, "tester")
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestGrantRoleUserNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.GrantRole(context.Background(), uuid.New(), "author", "Finance", nil, "tester")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGrantRoleScopedGrantAndRevoke(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-scoped", "sc@e", "SC")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	// Grant scoped role.
	u, err = s.GrantRole(ctx, u.ID, "author", "Facilities", nil, "op")
	if err != nil {
		t.Fatalf("GrantRole scoped: %v", err)
	}

	// Assert via direct SELECT on user_roles.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role='author' AND scope_category='Facilities'`,
		u.ID,
	).Scan(&count); err != nil {
		t.Fatalf("count scoped author rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 scoped author row, got %d", count)
	}

	// Revoke scoped role.
	u, err = s.RevokeRole(ctx, u.ID, "author", "Facilities", nil, "op")
	if err != nil {
		t.Fatalf("RevokeRole scoped: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id=$1 AND role='author' AND scope_category='Facilities'`,
		u.ID,
	).Scan(&count); err != nil {
		t.Fatalf("count scoped author rows after revoke: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 scoped author rows after revoke, got %d", count)
	}
}

func TestGrantRoleGlobalRejectsCategory(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-global-cat", "gc@e", "GC")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	// Global role must not carry a category.
	_, err = s.GrantRole(ctx, u.ID, "site-admin", "Nope", nil, "op")
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for global role with category, got %v", err)
	}
}

func TestGrantRoleScopedRejectsEmptyCategory(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-scoped-empty", "se@e", "SE")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	// Scoped role requires a non-empty category.
	_, err = s.GrantRole(ctx, u.ID, "approver", "", nil, "op")
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for scoped role with empty category, got %v", err)
	}
}

func TestJITUserHasNoStoredRoles(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	ju, err := s.JITProvision(ctx, "sub-jit", "j@x", "J")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}

	// JIT user has zero stored roles (reader is implicit).
	if len(ju.Roles) != 0 {
		t.Fatalf("expected 0 stored roles, got %v", ju.Roles)
	}

	// Direct DB verification.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_roles WHERE user_id = $1`, ju.ID,
	).Scan(&count); err != nil {
		t.Fatalf("count user_roles for JIT user: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 rows in user_roles for JIT user, got %d", count)
	}
}

func TestBootstrapAdmin(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u1, created, err := s.BootstrapAdmin(ctx, "kc-admin-1", "admin@example.org", "ssh-key")
	if err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	if !created {
		t.Fatal("expected created=true on first call")
	}
	if !containsString(u1.Roles, "site-admin") {
		t.Fatalf("expected site-admin role, got %v", u1.Roles)
	}
	// the dropped 'admin' role must NOT be seeded.
	if containsString(u1.Roles, "admin") {
		t.Fatalf("dropped role 'admin' must not be stored; roles: %v", u1.Roles)
	}
	// viewer must NOT be seeded.
	if containsString(u1.Roles, "viewer") {
		t.Fatalf("viewer must not be stored; roles: %v", u1.Roles)
	}

	// Second call returns existing admin, created=false.
	u2, created, err := s.BootstrapAdmin(ctx, "kc-admin-2", "other@example.org", "ssh-key")
	if err != nil {
		t.Fatalf("BootstrapAdmin (second): %v", err)
	}
	if created {
		t.Fatal("expected created=false when admin exists")
	}
	if u2.ID != u1.ID {
		t.Fatalf("expected same admin back, got %s vs %s", u1.ID, u2.ID)
	}
}

func TestAdminExists(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	ok, err := s.AdminExists(ctx)
	if err != nil {
		t.Fatalf("AdminExists: %v", err)
	}
	if ok {
		t.Fatal("expected no admin in fresh DB")
	}
	if _, _, err := s.BootstrapAdmin(ctx, "ka", "ka@e", "k"); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	ok, err = s.AdminExists(ctx)
	if err != nil {
		t.Fatalf("AdminExists: %v", err)
	}
	if !ok {
		t.Fatal("expected admin to exist")
	}
}

func TestGrantRole_AdminRejected(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-admin-dropped", "ad@e", "AD")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	if _, err := s.GrantRole(ctx, u.ID, "admin", "", nil, "test"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("granting dropped role 'admin' must error with ErrInvalid, got %v", err)
	}
}

func TestRevokeRole_RootKeepsSiteAdmin(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root, err := s.JITProvision(ctx, "sub-root-keep", "rk@e", "RK")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET is_root = true WHERE id = $1`, root.ID); err != nil {
		t.Fatalf("mark root: %v", err)
	}
	if _, err := s.GrantRole(ctx, root.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("grant site-admin: %v", err)
	}
	if _, err := s.RevokeRole(ctx, root.ID, "site-admin", "", nil, "test"); !errors.Is(err, store.ErrRootProtected) {
		t.Fatalf("revoking site-admin from root must error with ErrRootProtected, got %v", err)
	}
}

func containsString(haystack []string, needle string) bool {
	return slices.Contains(haystack, needle)
}
