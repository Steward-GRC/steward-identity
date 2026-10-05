// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// The read-only half of DeleteUser, gathered for the preview.

// TestDeletionPreflightCoversEveryTableDeleteUserClears is the DRIFT GUARD, and
// the reason DeleteUser and the counter share one table list.
//
// A delete preview that reports a different set of tables from the one the
// delete actually clears is worse than no preview, because an admin reads it and
// then acts on it. This test asserts three things at once: every table in the
// shared list has a count field (a new table without one makes
// UserAccessRowCounts return an error), every table actually has a row for the
// fixture user (so a count of 0 cannot pass vacuously), and DeleteUser really
// does clear all of them.
func TestDeletionPreflightCoversEveryTableDeleteUserClears(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	tables := store.DeletedAccessTables()
	if len(tables) == 0 {
		t.Fatal("DeletedAccessTables() is empty — the guard would pass vacuously")
	}

	u := seedFullyGrantedUser(t, pool, s, "pfall", "all@pf.example.org")

	// Non-zero control: every shared table must hold at least one row for this
	// user BEFORE the delete, or the post-delete zero proves nothing.
	for _, table := range tables {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM `+table+` WHERE user_id = $1`, u).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n == 0 {
			t.Fatalf("fixture seeded no row in %q — extend seedFullyGrantedUser, or this table's count can never be verified", table)
		}
	}

	counts, err := s.UserAccessRowCounts(ctx, u)
	if err != nil {
		t.Fatalf("UserAccessRowCounts: %v (a table in the shared list has no count field)", err)
	}
	for name, got := range map[string]int{
		"group_membership":      counts.GroupMemberships,
		"user_idp_groups":       counts.IdpGroups,
		"user_roles":            counts.Roles,
		"user_permissions":      counts.Permissions,
		"user_policy_overrides": counts.PolicyOverrides,
		"break_glass_grants":    counts.BreakGlassGrants,
	} {
		if got == 0 {
			t.Errorf("%s count is 0 but the table has rows — the count is not wired to the table", name)
		}
	}

	// group_managers is NOT in the shared list because DeleteUser does not clear
	// it. Pin that, so the preview's RETAINED_MANAGED_GROUPS warning stays true.
	for _, table := range tables {
		if table == "group_managers" {
			t.Fatalf("group_managers is in DeletedAccessTables() but DeleteUser does not clear it — one of the two changed without the other")
		}
	}
	if counts.ManagedGroups == 0 {
		t.Fatalf("fixture seeded no group_manager grant — the retained-grant assertion below cannot be verified")
	}

	if _, err := s.DeleteUser(ctx, u, nil, "test"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	after, err := s.UserAccessRowCounts(ctx, u)
	if err != nil {
		t.Fatalf("UserAccessRowCounts after delete: %v", err)
	}
	for name, got := range map[string]int{
		"group_membership":      after.GroupMemberships,
		"user_idp_groups":       after.IdpGroups,
		"user_roles":            after.Roles,
		"user_permissions":      after.Permissions,
		"user_policy_overrides": after.PolicyOverrides,
		"break_glass_grants":    after.BreakGlassGrants,
	} {
		if got != 0 {
			t.Errorf("%s still has %d row(s) after DeleteUser — the preview reports a class the delete does not clear", name, got)
		}
	}
	if after.ManagedGroups == 0 {
		t.Errorf("group_managers was cleared by DeleteUser after all — the preview's RETAINED_MANAGED_GROUPS warning is now a lie")
	}
}

// TestUserAccessRowCountsAreRawNotHydrated pins the place where counting from a
// hydrated User UNDER-reports what a delete removes.
//
// Only break-glass differs today. user_permissions is
// PRIMARY KEY (user_id, permission) with CHECK (permission IN
// ('policy.read_sensitive')), so an account can hold at most that single row
// and hydrateUser's bool happens to agree with the row count — the raw count is
// used anyway because DeleteUser deletes rows, and the bool starts
// under-reporting the moment that CHECK widens. This test asserts the schema
// constraint too, so widening it is a visible change rather than a silent one.
func TestUserAccessRowCountsAreRawNotHydrated(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.PreCreateLocalUser(ctx, "pfraw", "raw@pf.example.org", "Raw Counts")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	// 1. permissions. Only policy.read_sensitive is individually grantable
	// today; the CHECK constraint refuses anything else, which is exactly why
	// the bool and the count agree for now.
	if err := s.GrantPermission(ctx, u.ID, "policy.read_sensitive", nil, "test"); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_permissions (user_id, permission) VALUES ($1,'some.other.permission')`,
		u.ID); err == nil {
		t.Fatalf("user_permissions accepted an unlisted permission — the CHECK constraint widened, so hydrateUser's read_sensitive bool now under-reports and this test's premise has changed")
	}
	// 2. break-glass: ActiveBreakGlass filters expires_at > now() and applies
	// DISTINCT policy_number; DeleteUser deletes every row, and the table has no
	// uniqueness on (user_id, policy_number).
	if _, err := pool.Exec(ctx,
		`INSERT INTO break_glass_grants (user_id, policy_number, reason, expires_at)
		 VALUES ($1,'IT-001','live',now() + interval '1 hour'),
		        ($1,'IT-001','dup',now() + interval '1 hour'),
		        ($1,'IT-002','expired',now() - interval '1 hour')`,
		u.ID); err != nil {
		t.Fatalf("insert break-glass grants: %v", err)
	}

	counts, err := s.UserAccessRowCounts(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserAccessRowCounts: %v", err)
	}
	if counts.Permissions != 1 {
		t.Errorf("Permissions = %d, want 1 (the only individually-grantable permission)", counts.Permissions)
	}
	if counts.BreakGlassGrants != 3 {
		t.Errorf("BreakGlassGrants = %d, want 3 — ActiveBreakGlass would have reported 1 (live, de-duplicated)", counts.BreakGlassGrants)
	}

	perms, err := s.ListUserPermissions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserPermissions: %v", err)
	}
	if len(perms) != 1 || perms[0] != "policy.read_sensitive" {
		t.Fatalf("ListUserPermissions = %v, want [policy.read_sensitive]", perms)
	}
	// It must return a non-nil empty slice, not nil, for an account with none —
	// the preview renders a count from it.
	other, err := s.PreCreateLocalUser(ctx, "pfnoperm", "noperm@pf.example.org", "No Perms")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	if got, err := s.ListUserPermissions(ctx, other.ID); err != nil || got == nil || len(got) != 0 {
		t.Errorf("ListUserPermissions for a grant-less account = %v (err %v), want an empty non-nil slice", got, err)
	}
}

// TestUserDeletionPreflightSiblingAccounts pins the computable half of the
// note "deleting a user's only locally-authenticable account changes
// how they can get in". Identity cannot know two accounts are the same PERSON —
// only that they share an address — so the preflight reports exactly that.
func TestUserDeletionPreflightSiblingAccounts(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	const email = "heidi@example.org"
	subject, err := s.PreCreateLocalUser(ctx, "pfsubject", email, "Heidi Local")
	if err != nil {
		t.Fatalf("PreCreateLocalUser subject: %v", err)
	}

	pf, err := s.UserDeletionPreflight(ctx, subject.ID)
	if err != nil {
		t.Fatalf("UserDeletionPreflight: %v", err)
	}
	if pf.OtherLiveAccountsSameEmail != 0 || pf.OtherLocalAccountsSameEmail != 0 {
		t.Fatalf("a lone account has no siblings, got live=%d local=%d",
			pf.OtherLiveAccountsSameEmail, pf.OtherLocalAccountsSameEmail)
	}
	if !pf.User.LocalAccount {
		t.Fatalf("control: the fixture must be a local account")
	}

	// The incident shape: a FEDERATED sibling on the same address that cannot
	// sign in locally. It counts as a live sibling but NOT as a local one.
	var fedID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (external_subject, email, name, local_account)
		 VALUES ('', $1, 'Heidi Federated', false) RETURNING id`, email).Scan(&fedID); err != nil {
		t.Fatalf("insert federated sibling: %v", err)
	}
	pf, err = s.UserDeletionPreflight(ctx, subject.ID)
	if err != nil {
		t.Fatalf("UserDeletionPreflight: %v", err)
	}
	if pf.OtherLiveAccountsSameEmail != 1 {
		t.Errorf("OtherLiveAccountsSameEmail = %d, want 1", pf.OtherLiveAccountsSameEmail)
	}
	if pf.OtherLocalAccountsSameEmail != 0 {
		t.Errorf("OtherLocalAccountsSameEmail = %d, want 0 — a federated account cannot sign in without the IdP", pf.OtherLocalAccountsSameEmail)
	}

	// A TOMBSTONED sibling must not count at all: it cannot let anybody in.
	var deadID uuid.UUID
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (external_subject, email, name, local_account, deleted_at)
		 VALUES ('', $1, 'Heidi Deleted', true, now()) RETURNING id`, email).Scan(&deadID); err != nil {
		t.Fatalf("insert tombstoned sibling: %v", err)
	}
	pf, err = s.UserDeletionPreflight(ctx, subject.ID)
	if err != nil {
		t.Fatalf("UserDeletionPreflight: %v", err)
	}
	if pf.OtherLiveAccountsSameEmail != 1 {
		t.Errorf("a tombstoned sibling must not be counted as live, got %d", pf.OtherLiveAccountsSameEmail)
	}
	if pf.OtherLocalAccountsSameEmail != 0 {
		t.Errorf("a tombstoned local sibling must not be counted as locally-authenticable, got %d", pf.OtherLocalAccountsSameEmail)
	}

	// A LIVE local sibling is the one shape that makes the warning unnecessary.
	if _, err := s.PreCreateLocalUser(ctx, "pfsibling", email, "Heidi Second Local"); err != nil {
		t.Fatalf("PreCreateLocalUser sibling: %v", err)
	}
	pf, err = s.UserDeletionPreflight(ctx, subject.ID)
	if err != nil {
		t.Fatalf("UserDeletionPreflight: %v", err)
	}
	if pf.OtherLiveAccountsSameEmail != 2 {
		t.Errorf("OtherLiveAccountsSameEmail = %d, want 2", pf.OtherLiveAccountsSameEmail)
	}
	if pf.OtherLocalAccountsSameEmail != 1 {
		t.Errorf("OtherLocalAccountsSameEmail = %d, want 1", pf.OtherLocalAccountsSameEmail)
	}
}

// TestUserDeletionPreflightTombstonedAccountIsNotAnError: previewing a delete of
// an already-deleted account is legitimate — GetUser stays tombstone-blind by
// design — and must report the tombstone rather than 404.
func TestUserDeletionPreflightTombstonedAccountIsNotAnError(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.PreCreateLocalUser(ctx, "pfdead", "dead@pf.example.org", "Already Gone")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	if _, err := s.DeleteUser(ctx, u.ID, nil, "test"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	pf, err := s.UserDeletionPreflight(ctx, u.ID)
	if err != nil {
		t.Fatalf("previewing an already-deleted account must not error: %v", err)
	}
	if pf.User.DeletedAt == nil {
		t.Errorf("the preflight must report the tombstone so the preview can warn ALREADY_DELETED")
	}

	// A genuinely unknown id still 404s.
	if _, err := s.UserDeletionPreflight(ctx, uuid.New()); err != store.ErrNotFound {
		t.Errorf("unknown user must be ErrNotFound, got %v", err)
	}
}

// TestUserDeletionPreflightNamesGroups: the preview shows group names, not bare
// UUIDs, so an admin can recognise what access is being removed.
func TestUserDeletionPreflightNamesGroupsAndCountsPasskeys(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.PreCreateLocalUser(ctx, "pfgroups", "groups@pf.example.org", "Grouped")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	g, err := s.CreateGroup(ctx, "Finance", uuid.Nil, nil, nil, "test")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "test", ""); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_webauthn_credentials (user_id, credential_id, public_key, sign_count, created_at)
		 VALUES ($1, $2, $3, 0, now())`, u.ID, []byte("cred-1"), []byte("pk")); err != nil {
		t.Fatalf("insert passkey: %v", err)
	}

	pf, err := s.UserDeletionPreflight(ctx, u.ID)
	if err != nil {
		t.Fatalf("UserDeletionPreflight: %v", err)
	}
	if pf.GroupLabels[g.ID] != "Finance" {
		t.Errorf("group label = %q, want %q — a membership must not render as a UUID", pf.GroupLabels[g.ID], "Finance")
	}
	if pf.Passkeys != 1 {
		t.Errorf("Passkeys = %d, want 1 — a passkey makes the account locally authenticable", pf.Passkeys)
	}
}

// seedFullyGrantedUser creates a local user with at least one row in EVERY
// table DeleteUser clears, plus a group-manager grant (which it does not).
func seedFullyGrantedUser(t *testing.T, pool *pgxpool.Pool, s *store.Store, username, email string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	u, err := s.PreCreateLocalUser(ctx, username, email, "Fully Granted")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	g, err := s.CreateGroup(ctx, "Seeded "+username, uuid.Nil, nil, nil, "test")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "test", ""); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}
	if err := s.GrantGroupManager(ctx, u.ID, g.ID, nil, "test"); err != nil {
		t.Fatalf("GrantGroupManager: %v", err)
	}
	if _, err := s.GrantRole(ctx, u.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	if err := s.GrantPermission(ctx, u.ID, "policy.read_sensitive", nil, "test"); err != nil {
		t.Fatalf("GrantPermission: %v", err)
	}
	if _, err := s.SetPolicyOverride(ctx, u.ID, "IT-001", "deny", nil, "test"); err != nil {
		t.Fatalf("SetPolicyOverride: %v", err)
	}
	if _, err := s.GrantBreakGlass(ctx, u.ID, "IT-002", "testing", 60, nil); err != nil {
		t.Fatalf("GrantBreakGlass: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_idp_groups (user_id, idp_group_name) VALUES ($1, 'CN=Seeded')`, u.ID); err != nil {
		t.Fatalf("insert ad group: %v", err)
	}
	_ = time.Now
	return u.ID
}
