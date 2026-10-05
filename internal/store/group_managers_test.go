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

// TestGroupManagerGrantRevoke covers the group-manager grant lifecycle
// : grant is idempotent, IsGroupManager/ListManagedGroups reflect
// it, hydrateUser surfaces ManagedGroups, and revoke clears it.
func TestGroupManagerGrantRevoke(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-gm", "gm@e", "GM")
	g, _ := s.CreateGroup(ctx, "G", uuid.Nil, nil, nil, "tester")

	// Not a manager to start.
	if ok, err := s.IsGroupManager(ctx, u.ID, g.ID); err != nil || ok {
		t.Fatalf("IsGroupManager before grant: ok=%v err=%v", ok, err)
	}

	if err := s.GrantGroupManager(ctx, u.ID, g.ID, nil, "tester"); err != nil {
		t.Fatalf("GrantGroupManager: %v", err)
	}
	// Idempotent re-grant.
	if err := s.GrantGroupManager(ctx, u.ID, g.ID, nil, "tester"); err != nil {
		t.Fatalf("GrantGroupManager (again): %v", err)
	}

	if ok, err := s.IsGroupManager(ctx, u.ID, g.ID); err != nil || !ok {
		t.Fatalf("IsGroupManager after grant: ok=%v err=%v", ok, err)
	}
	managed, err := s.ListManagedGroups(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListManagedGroups: %v", err)
	}
	if len(managed) != 1 || managed[0] != g.ID {
		t.Fatalf("expected managed=[%s], got %v", g.ID, managed)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(got.ManagedGroups) != 1 || got.ManagedGroups[0] != g.ID {
		t.Fatalf("hydrateUser ManagedGroups=%v", got.ManagedGroups)
	}

	if err := s.RevokeGroupManager(ctx, u.ID, g.ID, nil, "tester"); err != nil {
		t.Fatalf("RevokeGroupManager: %v", err)
	}
	if ok, err := s.IsGroupManager(ctx, u.ID, g.ID); err != nil || ok {
		t.Fatalf("IsGroupManager after revoke: ok=%v err=%v", ok, err)
	}
}

// TestGroupManagerGrantUnknownUserOrGroup verifies the existence guards return
// ErrNotFound rather than a raw FK error.
func TestGroupManagerGrantUnknownUserOrGroup(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-gm2", "gm2@e", "GM2")
	g, _ := s.CreateGroup(ctx, "G2", uuid.Nil, nil, nil, "tester")

	if err := s.GrantGroupManager(ctx, uuid.New(), g.ID, nil, "t"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown user, got %v", err)
	}
	if err := s.GrantGroupManager(ctx, u.ID, uuid.New(), nil, "t"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown group, got %v", err)
	}
}

// TestMembershipProvenance covers source tracking: manual vs
// idp-sync memberships are recorded and surfaced on hydrateUser, and a
// group-manager (onlyManual) remove refuses a sync-owned row while a site-admin
// (onlyManual=false) may remove it.
func TestMembershipProvenance(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-prov", "prov@e", "P")
	gm, _ := s.CreateGroup(ctx, "manual-grp", uuid.Nil, nil, nil, "tester")
	gs, _ := s.CreateGroup(ctx, "sync-grp", uuid.Nil, nil, nil, "tester")

	if _, err := s.AddUserToGroup(ctx, u.ID, gm.ID, nil, "tester", store.SourceManual); err != nil {
		t.Fatalf("add manual: %v", err)
	}
	if _, err := s.AddUserToGroup(ctx, u.ID, gs.ID, nil, "sso-jit", store.SourceIdPSync); err != nil {
		t.Fatalf("add sync: %v", err)
	}

	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	srcByGroup := map[uuid.UUID]string{}
	for _, m := range got.Memberships {
		srcByGroup[m.GroupID] = m.Source
	}
	if srcByGroup[gm.ID] != store.SourceManual {
		t.Fatalf("manual group source=%q", srcByGroup[gm.ID])
	}
	if srcByGroup[gs.ID] != store.SourceIdPSync {
		t.Fatalf("sync group source=%q", srcByGroup[gs.ID])
	}

	// A group-manager (onlyManual=true) cannot remove the sync-owned row.
	err = s.RemoveUserFromGroup(ctx, u.ID, gs.ID, nil, "tester", true)
	if !errors.Is(err, store.ErrSyncOwned) {
		t.Fatalf("expected ErrSyncOwned removing sync row as manager, got %v", err)
	}
	// But the manual row is removable by a manager.
	if err := s.RemoveUserFromGroup(ctx, u.ID, gm.ID, nil, "tester", true); err != nil {
		t.Fatalf("manager remove manual: %v", err)
	}
	// A site-admin (onlyManual=false) may remove the sync-owned row.
	if err := s.RemoveUserFromGroup(ctx, u.ID, gs.ID, nil, "tester", false); err != nil {
		t.Fatalf("site-admin remove sync: %v", err)
	}
	got, _ = s.GetUser(ctx, u.ID)
	if len(got.Groups) != 0 {
		t.Fatalf("expected no memberships left, got %v", got.Groups)
	}

	// Removing a non-existent membership is an idempotent no-op even in
	// manager (onlyManual) mode.
	if err := s.RemoveUserFromGroup(ctx, u.ID, gm.ID, nil, "tester", true); err != nil {
		t.Fatalf("idempotent manager remove: %v", err)
	}
}

// TestAddUserToGroupRejectsBadSource guards the source vocabulary.
func TestAddUserToGroupRejectsBadSource(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-bs", "bs@e", "BS")
	g, _ := s.CreateGroup(ctx, "bs-grp", uuid.Nil, nil, nil, "tester")

	if _, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "t", "bogus"); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid for bad source, got %v", err)
	}
	// Empty source defaults to manual.
	if _, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "t", ""); err != nil {
		t.Fatalf("empty source should default to manual: %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if len(got.Memberships) != 1 || got.Memberships[0].Source != store.SourceManual {
		t.Fatalf("expected default manual membership, got %v", got.Memberships)
	}
}
