// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// TestReadListUsersByIdpGroups verifies that ListUsersByIdpGroups returns the
// mapped users whose identity provider group memberships intersect with the requested names.
func TestReadListUsersByIdpGroups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Provision two users and give them identity provider group memberships.
	u1, err := s.JITProvision(ctx, "kc-adgr-1", "adgr1@e", "AdGrUser1")
	if err != nil {
		t.Fatalf("JIT u1: %v", err)
	}
	u2, err := s.JITProvision(ctx, "kc-adgr-2", "adgr2@e", "AdGrUser2")
	if err != nil {
		t.Fatalf("JIT u2: %v", err)
	}
	u3, err := s.JITProvision(ctx, "kc-adgr-3", "adgr3@e", "AdGrUser3")
	if err != nil {
		t.Fatalf("JIT u3: %v", err)
	}

	if err := s.ReplaceUserIdpGroups(ctx, u1.ID, []string{"corp-vpn", "it-admin"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u1: %v", err)
	}
	if err := s.ReplaceUserIdpGroups(ctx, u2.ID, []string{"corp-vpn"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u2: %v", err)
	}
	if err := s.ReplaceUserIdpGroups(ctx, u3.ID, []string{"unrelated-group"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u3: %v", err)
	}

	h := handlers.NewReadHandler(s)

	// Request users in "corp-vpn" — should return u1 and u2 (not u3).
	resp, err := h.ListUsersByIdpGroups(ctx, &identityv1.ListUsersByIdpGroupsRequest{
		IdpGroupNames: []string{"corp-vpn"},
	})
	if err != nil {
		t.Fatalf("ListUsersByIdpGroups: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Fatalf("expected 2 users in corp-vpn, got %d", len(resp.Users))
	}
	foundIDs := map[string]bool{}
	for _, u := range resp.Users {
		foundIDs[u.Id] = true
	}
	if !foundIDs[u1.ID.String()] || !foundIDs[u2.ID.String()] {
		t.Fatalf("expected u1 and u2 in response, got %v", foundIDs)
	}

	// Request users in "it-admin" — should return only u1.
	resp2, err := h.ListUsersByIdpGroups(ctx, &identityv1.ListUsersByIdpGroupsRequest{
		IdpGroupNames: []string{"it-admin"},
	})
	if err != nil {
		t.Fatalf("ListUsersByIdpGroups it-admin: %v", err)
	}
	if len(resp2.Users) != 1 || resp2.Users[0].Id != u1.ID.String() {
		t.Fatalf("expected only u1 in it-admin, got %v", resp2.Users)
	}

	// Empty idp_group_names returns empty list (not an error).
	respEmpty, err := h.ListUsersByIdpGroups(ctx, &identityv1.ListUsersByIdpGroupsRequest{
		IdpGroupNames: nil,
	})
	if err != nil {
		t.Fatalf("ListUsersByIdpGroups empty: %v", err)
	}
	if len(respEmpty.Users) != 0 {
		t.Fatalf("expected 0 users for empty names, got %d", len(respEmpty.Users))
	}
}

// TestReadCountUsersByIdpGroups verifies that CountUsersByIdpGroups returns the
// distinct-user count for the supplied identity provider group names.
func TestReadCountUsersByIdpGroups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u1, err := s.JITProvision(ctx, "kc-adgc-1", "adgc1@e", "AdGcUser1")
	if err != nil {
		t.Fatalf("JIT u1: %v", err)
	}
	u2, err := s.JITProvision(ctx, "kc-adgc-2", "adgc2@e", "AdGcUser2")
	if err != nil {
		t.Fatalf("JIT u2: %v", err)
	}
	_ = u2

	if err := s.ReplaceUserIdpGroups(ctx, u1.ID, []string{"grp-a", "grp-b"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u1: %v", err)
	}
	if err := s.ReplaceUserIdpGroups(ctx, u2.ID, []string{"grp-b"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u2: %v", err)
	}

	h := handlers.NewReadHandler(s)

	// Count users in "grp-a" — only u1.
	respA, err := h.CountUsersByIdpGroups(ctx, &identityv1.CountUsersByIdpGroupsRequest{
		IdpGroupNames: []string{"grp-a"},
	})
	if err != nil {
		t.Fatalf("CountUsersByIdpGroups grp-a: %v", err)
	}
	if respA.Count != 1 {
		t.Fatalf("expected count=1 for grp-a, got %d", respA.Count)
	}

	// Count users in "grp-a" or "grp-b" — both u1 and u2, distinct count=2.
	respAB, err := h.CountUsersByIdpGroups(ctx, &identityv1.CountUsersByIdpGroupsRequest{
		IdpGroupNames: []string{"grp-a", "grp-b"},
	})
	if err != nil {
		t.Fatalf("CountUsersByIdpGroups grp-a+grp-b: %v", err)
	}
	if respAB.Count != 2 {
		t.Fatalf("expected count=2 for grp-a+grp-b, got %d", respAB.Count)
	}

	// Empty names returns count=0.
	respEmpty, err := h.CountUsersByIdpGroups(ctx, &identityv1.CountUsersByIdpGroupsRequest{
		IdpGroupNames: nil,
	})
	if err != nil {
		t.Fatalf("CountUsersByIdpGroups empty: %v", err)
	}
	if respEmpty.Count != 0 {
		t.Fatalf("expected count=0 for empty names, got %d", respEmpty.Count)
	}
}
