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

func TestCreateAndGetGroup(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	g, err := s.CreateGroup(ctx, "Engineering", uuid.Nil, map[string]string{"home": "true"}, nil, "tester")
	if err != nil {
		t.Fatalf("CreateGroup root: %v", err)
	}
	if g.Name != "Engineering" {
		t.Fatalf("name: %q", g.Name)
	}

	child, err := s.CreateGroup(ctx, "Platform", g.ID, nil, nil, "tester")
	if err != nil {
		t.Fatalf("CreateGroup child: %v", err)
	}
	if child.ParentID != g.ID {
		t.Fatalf("parent: got %s", child.ParentID)
	}

	got, err := s.GetGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.Metadata["home"] != "true" {
		t.Fatalf("metadata: %v", got.Metadata)
	}
}

func TestCreateGroupParentNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.CreateGroup(context.Background(), "Orphan", uuid.New(), nil, nil, "tester")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDeleteGroupRefusesNonEmpty(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	parent, _ := s.CreateGroup(ctx, "Parent", uuid.Nil, nil, nil, "tester")
	_, _ = s.CreateGroup(ctx, "Child", parent.ID, nil, nil, "tester")

	if err := s.DeleteGroup(ctx, parent.ID, nil, "tester"); !errors.Is(err, store.ErrHasChildren) {
		t.Fatalf("expected ErrHasChildren, got %v", err)
	}
}

func TestDeleteGroupRefusesWithMembers(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	g, _ := s.CreateGroup(ctx, "G", uuid.Nil, nil, nil, "tester")
	u, _ := s.JITProvision(ctx, "sub-d", "d@e", "D")
	if _, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "tester", "manual"); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}
	if err := s.DeleteGroup(ctx, g.ID, nil, "tester"); !errors.Is(err, store.ErrHasMembers) {
		t.Fatalf("expected ErrHasMembers, got %v", err)
	}
}

func TestRenameGroup(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	g, _ := s.CreateGroup(ctx, "Old", uuid.Nil, nil, nil, "tester")
	updated, err := s.RenameGroup(ctx, g.ID, "New", nil, "tester")
	if err != nil {
		t.Fatalf("RenameGroup: %v", err)
	}
	if updated.Name != "New" {
		t.Fatalf("name: %q", updated.Name)
	}
}

func TestSetGroupParentCycleRejected(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	a, _ := s.CreateGroup(ctx, "A", uuid.Nil, nil, nil, "tester")
	b, _ := s.CreateGroup(ctx, "B", a.ID, nil, nil, "tester")
	// Attempt: make A a child of B → would create A → B → A.
	_, err := s.SetGroupParent(ctx, a.ID, b.ID, nil, "tester")
	if !errors.Is(err, store.ErrCycle) {
		t.Fatalf("expected ErrCycle, got %v", err)
	}
}

func TestSetGroupParentSelfRejected(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	a, _ := s.CreateGroup(ctx, "A", uuid.Nil, nil, nil, "tester")
	_, err := s.SetGroupParent(ctx, a.ID, a.ID, nil, "tester")
	if !errors.Is(err, store.ErrCycle) {
		t.Fatalf("expected ErrCycle, got %v", err)
	}
}

func TestListDescendantsAndAncestors(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	root, _ := s.CreateGroup(ctx, "root", uuid.Nil, nil, nil, "tester")
	mid, _ := s.CreateGroup(ctx, "mid", root.ID, nil, nil, "tester")
	leaf, _ := s.CreateGroup(ctx, "leaf", mid.ID, nil, nil, "tester")

	desc, err := s.ListDescendants(ctx, root.ID)
	if err != nil {
		t.Fatalf("ListDescendants: %v", err)
	}
	if len(desc) != 2 {
		t.Fatalf("expected 2 descendants, got %d", len(desc))
	}

	anc, err := s.ListAncestors(ctx, leaf.ID)
	if err != nil {
		t.Fatalf("ListAncestors: %v", err)
	}
	if len(anc) != 2 || anc[0].ID != mid.ID || anc[1].ID != root.ID {
		t.Fatalf("ancestor chain wrong: %+v", anc)
	}
}
