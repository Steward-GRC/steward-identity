// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

func containsUser(users []store.User, id uuid.UUID) bool {
	for _, u := range users {
		if u.ID == id {
			return true
		}
	}
	return false
}

// TestListUsersByEmailExcludesTombstonedKeepsDisabled pins search
// excluding deleted accounts. The user-picker typeahead (gateway searchUsers -> account-merge
// pickers, RACI SubjectSelect, group member pickers) must never offer a
// tombstoned (merged-away / soft-deleted) account: an admin picking one as a
// merge TARGET would migrate live records onto a deleted account.
//
// It simultaneously pins the deliberate NON-filter: a merely-disabled account
// (enabled=false, deleted_at IS NULL) MUST stay in the results, because a
// disabled duplicate is the canonical account-merge SOURCE.
func TestListUsersByEmailExcludesTombstonedKeepsDisabled(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	active, err := s.PreCreateLocalUser(ctx, "tsactive", "active@ts.example.org", "Active User")
	if err != nil {
		t.Fatalf("PreCreateLocalUser active: %v", err)
	}
	disabled, err := s.PreCreateLocalUser(ctx, "tsdisabled", "disabled@ts.example.org", "Disabled Dup")
	if err != nil {
		t.Fatalf("PreCreateLocalUser disabled: %v", err)
	}
	deleted, err := s.PreCreateLocalUser(ctx, "tsdeleted", "deleted@ts.example.org", "Deleted User")
	if err != nil {
		t.Fatalf("PreCreateLocalUser deleted: %v", err)
	}
	merged, err := s.PreCreateLocalUser(ctx, "tsmerged", "merged@ts.example.org", "Merged Away")
	if err != nil {
		t.Fatalf("PreCreateLocalUser merged: %v", err)
	}

	// Disabled but NOT deleted: the merge-source case that must survive.
	if _, err := s.SetEnabled(ctx, disabled.ID, false, nil, "test"); err != nil {
		t.Fatalf("SetEnabled disabled: %v", err)
	}
	// Soft-deleted (tombstone).
	if _, err := s.DeleteUser(ctx, deleted.ID, nil, "test"); err != nil {
		t.Fatalf("DeleteUser deleted: %v", err)
	}
	// Merged-away tombstone: deleted_at + merged_into_user_id + enabled=false,
	// exactly the shape TombstoneMergedSource leaves behind.
	if _, err := pool.Exec(ctx,
		`UPDATE users
		    SET deleted_at = now(), merged_into_user_id = $2, enabled = false
		  WHERE id = $1`, merged.ID, active.ID); err != nil {
		t.Fatalf("tombstone merged source: %v", err)
	}

	got, err := s.ListUsersByEmail(ctx, "ts.example.org", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("ListUsersByEmail: %v", err)
	}

	if !containsUser(got, active.ID) {
		t.Errorf("active user missing from search results (got %d users)", len(got))
	}
	if !containsUser(got, disabled.ID) {
		t.Errorf("disabled-but-not-deleted user must stay IN results (it is the canonical merge source); got %d users", len(got))
	}
	if containsUser(got, deleted.ID) {
		t.Errorf("soft-deleted (tombstoned) user must NOT be returned by search")
	}
	if containsUser(got, merged.ID) {
		t.Errorf("merged-away (tombstoned) user must NOT be returned by search")
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 live users, got %d", len(got))
	}

	// The empty-substring "list all" branch must exclude tombstones too — the
	// picker opens with no query typed.
	all, err := s.ListUsersByEmail(ctx, "", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("ListUsersByEmail empty: %v", err)
	}
	if containsUser(all, deleted.ID) || containsUser(all, merged.ID) {
		t.Errorf("empty-substring search leaked a tombstoned user")
	}
	if !containsUser(all, disabled.ID) {
		t.Errorf("empty-substring search dropped the disabled-but-not-deleted user")
	}
}

// TestListUsersByEmailKeysetStableWithTombstonesInterleaved proves the new
// predicate does not break the (email, id) keyset cursor: with tombstoned rows
// interleaved between live ones in email order, paging must return every live
// row exactly once, in order, and must not skip past a live row because a
// tombstone was filtered out of the page.
func TestListUsersByEmailKeysetStableWithTombstonesInterleaved(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// Emails sort ks1 < ks2 < ... < ks6; the even ones get tombstoned so a
	// tombstone sits between every pair of live rows.
	type fixture struct {
		email string
		user  store.User
		live  bool
	}
	fixtures := []fixture{
		{email: "ks1@keyset.example.org", live: true},
		{email: "ks2@keyset.example.org", live: false},
		{email: "ks3@keyset.example.org", live: true},
		{email: "ks4@keyset.example.org", live: false},
		{email: "ks5@keyset.example.org", live: true},
		{email: "ks6@keyset.example.org", live: false},
	}
	var wantLive []string
	for i := range fixtures {
		u, err := s.PreCreateLocalUser(ctx, "keyset"+fixtures[i].email[2:3], fixtures[i].email, "Keyset "+fixtures[i].email)
		if err != nil {
			t.Fatalf("PreCreateLocalUser %s: %v", fixtures[i].email, err)
		}
		fixtures[i].user = u
		if fixtures[i].live {
			wantLive = append(wantLive, fixtures[i].email)
			continue
		}
		if _, err := s.DeleteUser(ctx, u.ID, nil, "test"); err != nil {
			t.Fatalf("DeleteUser %s: %v", fixtures[i].email, err)
		}
	}

	// Page with limit 2 until exhausted, advancing the cursor exactly the way
	// the read handler does (last returned row's email + id).
	const limit = 2
	var (
		seen        []string
		cursorEmail string
		cursorID    = uuid.Nil
	)
	for page := range 10 {
		got, err := s.ListUsersByEmail(ctx, "keyset.example.org", limit, cursorEmail, cursorID)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		for _, u := range got {
			seen = append(seen, u.Email)
		}
		if len(got) < limit {
			break
		}
		last := got[len(got)-1]
		cursorEmail, cursorID = last.Email, last.ID
	}

	if len(seen) != len(wantLive) {
		t.Fatalf("paged %d rows, want %d live rows: got %v want %v", len(seen), len(wantLive), seen, wantLive)
	}
	for i := range wantLive {
		if seen[i] != wantLive[i] {
			t.Fatalf("keyset paging out of order or skipping: got %v want %v", seen, wantLive)
		}
	}

	// No repeats — a broken cursor would re-emit a row.
	uniq := map[string]int{}
	for _, e := range seen {
		uniq[e]++
		if uniq[e] > 1 {
			t.Fatalf("keyset paging repeated %s: %v", e, seen)
		}
	}
}

// TestGetUserStillReturnsTombstonedUser pins the deliberate asymmetry:
// SEARCH excludes tombstoned users, RESOLVE does not. GetUser
// backs the gateway's user-label resolution, and historical audit,
// acknowledgment and approval rows legitimately reference merged-away user ids.
// Filtering here would render raw UUIDs instead of real names across the whole
// audit history — the defect this guards against. If this test
// ever fails, a deleted_at filter has leaked into the resolve path.
func TestGetUserStillReturnsTombstonedUser(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	target, err := s.PreCreateLocalUser(ctx, "resolvetarget", "target@resolve.example.org", "Survivor Account")
	if err != nil {
		t.Fatalf("PreCreateLocalUser target: %v", err)
	}
	source, err := s.PreCreateLocalUser(ctx, "resolvesource", "source@resolve.example.org", "Merged Away Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser source: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users
		    SET deleted_at = now(), merged_into_user_id = $2, enabled = false
		  WHERE id = $1`, source.ID, target.ID); err != nil {
		t.Fatalf("tombstone merged source: %v", err)
	}

	// The search path must not offer it...
	found, err := s.ListUsersByEmail(ctx, "resolve.example.org", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("ListUsersByEmail: %v", err)
	}
	if containsUser(found, source.ID) {
		t.Errorf("tombstoned user leaked into search")
	}

	// ...but the resolve path MUST still yield its display name.
	byID, err := s.GetUser(ctx, source.ID)
	if err != nil {
		t.Fatalf("GetUser on tombstoned user must still succeed (audit label resolution): %v", err)
	}
	if byID.Name != "Merged Away Person" {
		t.Errorf("GetUser lost the tombstoned user's display name: got %q", byID.Name)
	}
	if byID.Email != "source@resolve.example.org" {
		t.Errorf("GetUser lost the tombstoned user's email: got %q", byID.Email)
	}

	// GetUserByEmail / GetUserByUsername are the other single-row lookups on
	// this table; they must stay tombstone-blind as well.
	byEmail, err := s.GetUserByEmail(ctx, "source@resolve.example.org")
	if err != nil {
		t.Fatalf("GetUserByEmail on tombstoned user must still succeed: %v", err)
	}
	if byEmail.ID != source.ID {
		t.Errorf("GetUserByEmail resolved the wrong row: %s", byEmail.ID)
	}
	byUsername, err := s.GetUserByUsername(ctx, "resolvesource")
	if err != nil {
		t.Fatalf("GetUserByUsername on tombstoned user must still succeed: %v", err)
	}
	if byUsername.ID != source.ID {
		t.Errorf("GetUserByUsername resolved the wrong row: %s", byUsername.ID)
	}
}
