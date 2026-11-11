// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestListGroupNamesByUser pins the order the ack roster shows: a user's
// direct group names by name without regard to case, then by group id, so two
// reads of the same membership always agree.
func TestListGroupNamesByUser(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	a, _ := s.JITProvision(ctx, "su-gn-a", "gn-a@e", "A")
	b, _ := s.JITProvision(ctx, "su-gn-b", "gn-b@e", "B")
	none, _ := s.JITProvision(ctx, "su-gn-none", "gn-none@e", "None")

	finance, err := s.CreateGroup(ctx, "Finance team", uuid.Nil, nil, nil, "tester")
	if err != nil {
		t.Fatal(err)
	}
	approvers, _ := s.CreateGroup(ctx, "approvers", uuid.Nil, nil, nil, "tester")
	zed, _ := s.CreateGroup(ctx, "Zed", uuid.Nil, nil, nil, "tester")
	// A child group the user is not a direct member of must not appear.
	child, _ := s.CreateGroup(ctx, "Child", finance.ID, nil, nil, "tester")
	_ = child

	for _, g := range []uuid.UUID{zed.ID, finance.ID, approvers.ID} {
		if _, err := s.AddUserToGroup(ctx, a.ID, g, nil, "t", "manual"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddUserToGroup(ctx, b.ID, zed.ID, nil, "t", "manual"); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListGroupNamesByUser(ctx, []uuid.UUID{a.ID, b.ID, none.ID, uuid.New()})
	if err != nil {
		t.Fatalf("ListGroupNamesByUser: %v", err)
	}
	want := []string{"approvers", "Finance team", "Zed"}
	if len(got[a.ID]) != len(want) {
		t.Fatalf("user a groups = %v, want %v", got[a.ID], want)
	}
	for i := range want {
		if got[a.ID][i] != want[i] {
			t.Fatalf("user a groups = %v, want %v", got[a.ID], want)
		}
	}
	if len(got[b.ID]) != 1 || got[b.ID][0] != "Zed" {
		t.Fatalf("user b groups = %v, want [Zed]", got[b.ID])
	}
	if len(got[none.ID]) != 0 {
		t.Fatalf("user with no groups = %v, want none", got[none.ID])
	}

	empty, err := s.ListGroupNamesByUser(ctx, nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("no ids: got %v, %v", empty, err)
	}
}
