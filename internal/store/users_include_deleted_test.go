// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// Search excludes tombstoned accounts, which left NO surface in the product listed a soft-deleted account. The admin
// directory resolver calls the same RPC as the typeahead, so an administrator
// investigating "where did this person's records go" could not see that the
// account had ever existed. SearchUsers gains an opt-in.

// TestSearchUsersIncludeDeletedSurfacesTombstones proves the opt-in returns
// tombstoned rows WITH the fields an admin needs to act on them — the tombstone
// stamp and, for a merged-away account, the surviving account to follow to.
func TestSearchUsersIncludeDeletedSurfacesTombstones(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	live, err := s.PreCreateLocalUser(ctx, "inclive", "live@incl.example.org", "Live Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	deleted, err := s.PreCreateLocalUser(ctx, "incldeleted", "deleted@incl.example.org", "Deleted Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser deleted: %v", err)
	}
	merged, err := s.PreCreateLocalUser(ctx, "inclmerged", "merged@incl.example.org", "Merged Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser merged: %v", err)
	}
	if _, err := s.DeleteUser(ctx, deleted.ID, nil, "test"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET deleted_at = now(), merged_into_user_id = $2, enabled = false WHERE id = $1`,
		merged.ID, live.ID); err != nil {
		t.Fatalf("tombstone merged source: %v", err)
	}

	// Default (the picker) is unchanged: tombstones stay out.
	def, err := s.SearchUsers(ctx, store.UserSearchOpts{Substring: "incl.example.org", Limit: 200})
	if err != nil {
		t.Fatalf("SearchUsers default: %v", err)
	}
	if containsUser(def, deleted.ID) || containsUser(def, merged.ID) {
		t.Errorf("IncludeDeleted defaults to false; a tombstone leaked into the picker result")
	}
	if !containsUser(def, live.ID) {
		t.Fatalf("control: the live user must be in the default result (got %d)", len(def))
	}

	// The admin directory opt-in.
	got, err := s.SearchUsers(ctx, store.UserSearchOpts{Substring: "incl.example.org", Limit: 200, IncludeDeleted: true})
	if err != nil {
		t.Fatalf("SearchUsers IncludeDeleted: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("IncludeDeleted returned %d users, want 3 (live + deleted + merged)", len(got))
	}
	byID := map[uuid.UUID]store.User{}
	for _, u := range got {
		byID[u.ID] = u
	}
	if u := byID[live.ID]; u.Tombstoned() {
		t.Errorf("the live user must not be marked tombstoned")
	} else if u.MergedIntoUserID != nil {
		t.Errorf("the live user must have no merged_into_user_id")
	}
	du, ok := byID[deleted.ID]
	if !ok {
		t.Fatalf("the soft-deleted user is missing from the IncludeDeleted result")
	}
	if !du.Tombstoned() {
		t.Errorf("the soft-deleted user must report Tombstoned() and carry DeletedAt")
	}
	if du.MergedIntoUserID != nil {
		t.Errorf("a delete-outright tombstone must have NO merged_into_user_id, got %v", du.MergedIntoUserID)
	}
	mu, ok := byID[merged.ID]
	if !ok {
		t.Fatalf("the merged-away user is missing from the IncludeDeleted result")
	}
	if !mu.Tombstoned() {
		t.Errorf("the merged-away user must report Tombstoned()")
	}
	if mu.MergedIntoUserID == nil || *mu.MergedIntoUserID != live.ID {
		t.Errorf("merged-away user must name its surviving account %s, got %v", live.ID, mu.MergedIntoUserID)
	}
}

// TestSearchUsersIncludeDeletedKeysetStable pins that the opt-in does not break
// the (email, id) cursor: with include_deleted the tombstones are IN the row set
// the keyset walks, so every row must still come back exactly once, in order.
func TestSearchUsersIncludeDeletedKeysetStable(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	var want []string
	for i, name := range []string{"ik1", "ik2", "ik3", "ik4", "ik5", "ik6"} {
		u, err := s.PreCreateLocalUser(ctx, name, name+"@inclkey.example.org", "Incl "+name)
		if err != nil {
			t.Fatalf("PreCreateLocalUser %s: %v", name, err)
		}
		want = append(want, u.Email)
		if i%2 == 1 {
			if _, err := s.DeleteUser(ctx, u.ID, nil, "test"); err != nil {
				t.Fatalf("DeleteUser %s: %v", name, err)
			}
		}
	}

	const limit = 2
	var (
		seen        []string
		cursorEmail string
		cursorID    = uuid.Nil
	)
	for page := range 10 {
		got, err := s.SearchUsers(ctx, store.UserSearchOpts{
			Substring: "inclkey.example.org", Limit: limit,
			CursorEmail: cursorEmail, CursorID: cursorID, IncludeDeleted: true,
		})
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
	if len(seen) != len(want) {
		t.Fatalf("paged %d rows with IncludeDeleted, want %d: got %v", len(seen), len(want), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("IncludeDeleted keyset out of order: got %v want %v", seen, want)
		}
	}
}

// TestListUsersByEmailStillExcludesTombstones pins that the pre-existing
// 5-argument wrapper keeps its live-only behaviour, so the 16 existing call
// sites (and any caller that has not opted in) cannot become tombstone-visible
// by accident.
func TestListUsersByEmailStillExcludesTombstones(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	live, err := s.PreCreateLocalUser(ctx, "wraplive", "live@wrap.example.org", "Live")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	dead, err := s.PreCreateLocalUser(ctx, "wrapdead", "dead@wrap.example.org", "Dead")
	if err != nil {
		t.Fatalf("PreCreateLocalUser dead: %v", err)
	}
	if _, err := s.DeleteUser(ctx, dead.ID, nil, "test"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	got, err := s.ListUsersByEmail(ctx, "wrap.example.org", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("ListUsersByEmail: %v", err)
	}
	if !containsUser(got, live.ID) {
		t.Errorf("control: live user missing (got %d)", len(got))
	}
	if containsUser(got, dead.ID) {
		t.Errorf("the legacy wrapper must stay live-only")
	}
}
