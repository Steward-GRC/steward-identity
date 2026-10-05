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

func TestCreateGroupDuplicateName(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	if _, err := s.CreateGroup(ctx, "Dup", uuid.Nil, nil, nil, "t"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreateGroup(ctx, "Dup", uuid.Nil, nil, nil, "t")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestRenameGroupDuplicateName(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	a, _ := s.CreateGroup(ctx, "A", uuid.Nil, nil, nil, "t")
	if _, err := s.CreateGroup(ctx, "B", uuid.Nil, nil, nil, "t"); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	// Renaming A to B should collide with the root-name unique index.
	_, err := s.RenameGroup(ctx, a.ID, "B", nil, "t")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestCreateGroupEmptyName(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.CreateGroup(context.Background(), "", uuid.Nil, nil, nil, "t")
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestRenameGroupNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.RenameGroup(context.Background(), uuid.New(), "New", nil, "t")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetGroupParentNonexistentParent(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	g, _ := s.CreateGroup(ctx, "G", uuid.Nil, nil, nil, "t")
	_, err := s.SetGroupParent(ctx, g.ID, uuid.New(), nil, "t")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetEnabledNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.SetEnabled(context.Background(), uuid.New(), false, nil, "t")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAddUserToGroupUserNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	g, _ := s.CreateGroup(ctx, "G", uuid.Nil, nil, nil, "t")
	_, err := s.AddUserToGroup(ctx, uuid.New(), g.ID, nil, "t", "manual")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAddUserToGroupGroupNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, _ := s.JITProvision(ctx, "k", "u@e", "U")
	_, err := s.AddUserToGroup(ctx, u.ID, uuid.New(), nil, "t", "manual")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRevokeRoleInvalid(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, _ := s.JITProvision(ctx, "k", "u@e", "U")
	_, err := s.RevokeRole(ctx, u.ID, "badrole", "", nil, "t")
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestRevokeRoleUserNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.RevokeRole(context.Background(), uuid.New(), "author", "Facilities", nil, "t")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetUserByExternalSubjectNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.GetUserByExternalSubject(context.Background(), "never-existed")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
