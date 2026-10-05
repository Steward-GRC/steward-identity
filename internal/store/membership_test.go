// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestAddRemoveMembership(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-m", "m@e", "M")
	g, _ := s.CreateGroup(ctx, "G", uuid.Nil, nil, nil, "tester")

	changed, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "tester", "manual")
	if err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true on first add")
	}
	// Idempotent: re-add is a no-op.
	changed, err = s.AddUserToGroup(ctx, u.ID, g.ID, nil, "tester", "manual")
	if err != nil {
		t.Fatalf("AddUserToGroup (again): %v", err)
	}
	if changed {
		t.Fatalf("expected changed=false on re-add no-op")
	}

	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(got.Groups) != 1 || got.Groups[0] != g.ID {
		t.Fatalf("expected one group %s, got %v", g.ID, got.Groups)
	}

	if err := s.RemoveUserFromGroup(ctx, u.ID, g.ID, nil, "tester", false); err != nil {
		t.Fatalf("RemoveUserFromGroup: %v", err)
	}
	got, err = s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(got.Groups) != 0 {
		t.Fatalf("expected no groups, got %v", got.Groups)
	}
}

func TestListUsersInGroupWithDescendants(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	root, _ := s.CreateGroup(ctx, "root", uuid.Nil, nil, nil, "tester")
	child, _ := s.CreateGroup(ctx, "child", root.ID, nil, nil, "tester")
	u1, _ := s.JITProvision(ctx, "su-1", "u1@e", "U1")
	u2, _ := s.JITProvision(ctx, "su-2", "u2@e", "U2")

	if _, err := s.AddUserToGroup(ctx, u1.ID, root.ID, nil, "t", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUserToGroup(ctx, u2.ID, child.ID, nil, "t", "manual"); err != nil {
		t.Fatal(err)
	}

	direct, err := s.ListUsersInGroup(ctx, root.ID, false)
	if err != nil {
		t.Fatalf("ListUsersInGroup direct: %v", err)
	}
	if len(direct) != 1 {
		t.Fatalf("expected 1 direct user, got %d", len(direct))
	}

	withDesc, err := s.ListUsersInGroup(ctx, root.ID, true)
	if err != nil {
		t.Fatalf("ListUsersInGroup withDesc: %v", err)
	}
	if len(withDesc) != 2 {
		t.Fatalf("expected 2 with descendants, got %d", len(withDesc))
	}
}

func TestListUserGroups(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "su-ug", "ug@e", "UG")
	root, _ := s.CreateGroup(ctx, "root", uuid.Nil, nil, nil, "tester")
	child, _ := s.CreateGroup(ctx, "child", root.ID, nil, nil, "tester")
	leaf, _ := s.CreateGroup(ctx, "leaf", child.ID, nil, nil, "tester")
	_ = leaf
	if _, err := s.AddUserToGroup(ctx, u.ID, root.ID, nil, "t", "manual"); err != nil {
		t.Fatal(err)
	}

	direct, err := s.ListUserGroups(ctx, u.ID, false)
	if err != nil {
		t.Fatalf("ListUserGroups direct: %v", err)
	}
	if len(direct) != 1 {
		t.Fatalf("expected 1 direct group, got %d", len(direct))
	}

	expanded, err := s.ListUserGroups(ctx, u.ID, true)
	if err != nil {
		t.Fatalf("ListUserGroups expanded: %v", err)
	}
	if len(expanded) != 3 {
		t.Fatalf("expected 3 expanded groups (root + child + leaf), got %d", len(expanded))
	}
}
