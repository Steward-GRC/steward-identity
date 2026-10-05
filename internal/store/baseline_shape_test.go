// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestBaselineSSOTablesExist verifies the baseline created every SSO table.
func TestBaselineSSOTablesExist(t *testing.T) {
	pool := newTestDB(t)
	ctx := context.Background()
	for _, tbl := range []string{"sso_domains", "idp_connections", "idp_group_mappings", "domain_verification", "sp_certificates"} {
		var reg string
		err := pool.QueryRow(ctx, "SELECT to_regclass($1)", "public."+tbl).Scan(&reg)
		require.NoError(t, err)
		// to_regclass returns the unqualified relation name when it's
		// resolvable via the default search_path (public is always on it).
		require.Equal(t, tbl, reg, "table %s missing", tbl)
	}
}

// TestBaselineRolesConstraints checks the role vocabulary and the category
// scoping the baseline enforces.
func TestBaselineRolesConstraints(t *testing.T) {
	pool := newTestDB(t)
	ctx := context.Background()

	// Seed a user directly.
	var uid uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (external_subject, email) VALUES ('sub-1','erin@example.org') RETURNING id`).Scan(&uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Global role with empty scope: allowed.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1,'site-admin','')`, uid); err != nil {
		t.Fatalf("global site-admin insert should succeed: %v", err)
	}
	// The retired 'admin' role is rejected by the role check.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1,'admin','')`, uid); err == nil {
		t.Fatal("dropped role 'admin' must be rejected by role_check constraint")
	}
	// Scoped author with a category: allowed.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1,'author','Facilities')`, uid); err != nil {
		t.Fatalf("scoped author insert should succeed: %v", err)
	}
	// Author WITHOUT a category: rejected by scope check.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1,'author','')`, uid); err == nil {
		t.Fatal("author without category must be rejected")
	}
	// Legacy role 'viewer': rejected by role check.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1,'viewer','')`, uid); err == nil {
		t.Fatal("legacy role 'viewer' must be rejected")
	}
	// Same author scoped to a second category: allowed (PK includes scope).
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1,'author','Travel')`, uid); err != nil {
		t.Fatalf("second-category author should succeed: %v", err)
	}
}

// TestBaselineHasNoRetiredTables pins what the baseline leaves out: sessions
// live in the sign-in service, audit events wait in the go-outbox table, and
// identity provider groups replaced the directory group table.
func TestBaselineHasNoRetiredTables(t *testing.T) {
	pool := newTestDB(t)
	ctx := context.Background()
	for _, tbl := range []string{"sessions", "audit_buffer", "user_ad_groups", "user_group_exclusions"} {
		var reg *string
		require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass($1)::text", "public."+tbl).Scan(&reg))
		require.Nil(t, reg, "table %s must not exist", tbl)
	}
	for _, tbl := range []string{"user_idp_groups", "audit_outbox"} {
		var reg *string
		require.NoError(t, pool.QueryRow(ctx, "SELECT to_regclass($1)::text", "public."+tbl).Scan(&reg))
		require.NotNil(t, reg, "table %s missing", tbl)
	}
}
