// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// A typeahead has to find a person by any of the ways the person is known:
// first name, last name, full name, username or e-mail, in any case
// (steward-identity#37). Pinned here because the picker depends on it.
func TestSearchUsersMatchesNamesUsernameAndEmail(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	ivan, err := s.JITProvisionWithNames(ctx, "sub-find-ivan", "ivan.ive@find.example.org", "Ivan Ive", "Ivan", "Ive")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	other, err := s.JITProvisionWithNames(ctx, "sub-find-other", "someone@find.example.org", "Someone Else", "Someone", "Else")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	local, err := s.PreCreateLocalUser(ctx, "findlocal", "fl@find.example.org", "Fiona Local")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	for _, q := range []string{"ivan", "IVE", "ivan ive", "Ivan Ive", "ivan.ive@", "find.example.org"} {
		got, err := s.SearchUsers(ctx, store.UserSearchOpts{Substring: q, Limit: 50})
		if err != nil {
			t.Fatalf("search %q: %v", q, err)
		}
		if !containsUser(got, ivan.ID) {
			t.Errorf("search %q did not find Ivan Ive", q)
		}
		if q != "find.example.org" && containsUser(got, other.ID) {
			t.Errorf("search %q returned an unrelated person", q)
		}
	}
	got, err := s.SearchUsers(ctx, store.UserSearchOpts{Substring: "findloc", Limit: 50})
	if err != nil || !containsUser(got, local.ID) {
		t.Fatalf("a username search did not find the local account: %v", err)
	}
	got, err = s.SearchUsers(ctx, store.UserSearchOpts{Substring: "zzz-nobody", Limit: 50})
	if err != nil || len(got) != 0 {
		t.Fatalf("an unmatched query returned %d users (%v)", len(got), err)
	}
}

func groupNames(gs []store.Group) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	return out
}

func TestSearchGroupsMatchesTheNameCaseInsensitivelyAtAnyDepth(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	root, err := s.CreateGroup(ctx, "Finance Team", uuid.Nil, nil, nil, "test")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.CreateGroup(ctx, "Treasury Finance", root.ID, nil, nil, "test"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.CreateGroup(ctx, "Legal", uuid.Nil, nil, nil, "test"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.SearchGroups(ctx, "fINAN", 20)
	if err != nil {
		t.Fatalf("SearchGroups: %v", err)
	}
	if names := groupNames(got); len(names) != 2 || names[0] != "Finance Team" || names[1] != "Treasury Finance" {
		t.Fatalf("want both finance groups ordered by name, got %v", names)
	}
	got, _ = s.SearchGroups(ctx, "nothing-like-this", 20)
	if len(got) != 0 {
		t.Fatalf("unmatched query returned %v", groupNames(got))
	}
}

// The query is text, not a pattern: a percent or underscore must not widen the
// match to the whole directory.
func TestSearchGroupsTreatsWildcardsAsText(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	for _, n := range []string{"Ops 100% Uptime", "Ops Plain", "Ops_Team", "OpsXTeam"} {
		if _, err := s.CreateGroup(ctx, n, uuid.Nil, nil, nil, "test"); err != nil {
			t.Fatalf("seed %q: %v", n, err)
		}
	}
	got, _ := s.SearchGroups(ctx, "%", 20)
	if names := groupNames(got); len(names) != 1 || names[0] != "Ops 100% Uptime" {
		t.Fatalf("%% matched %v, want only the group with a percent in its name", names)
	}
	got, _ = s.SearchGroups(ctx, "ops_team", 20)
	if names := groupNames(got); len(names) != 1 || names[0] != "Ops_Team" {
		t.Fatalf("_ matched %v, want only Ops_Team", names)
	}
}

func TestSearchGroupsCapsTheResult(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	for _, n := range []string{"Cap A", "Cap B", "Cap C"} {
		if _, err := s.CreateGroup(ctx, n, uuid.Nil, nil, nil, "test"); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	got, err := s.SearchGroups(ctx, "cap", 2)
	if err != nil || len(got) != 2 {
		t.Fatalf("want 2 of 3 under the limit, got %d (%v)", len(got), err)
	}
}
