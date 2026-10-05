// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// TestListUsersByEmailIncludeDeleted is the RPC-level regression.
//
// The gateway's admin directory resolver calls THIS RPC — the same one the
// typeahead calls — so's tombstone exclusion removed soft-deleted
// accounts from the admin Users list as well, leaving no surface in the product
// that showed one. include_deleted is the narrow opt-in; the default must stay
// exclusive, because a picker offering a merged-away account is the original
// defect.
func TestListUsersByEmailIncludeDeleted(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewReadHandler(s)
	ctx := context.Background()

	live, err := s.PreCreateLocalUser(ctx, "rpclive", "live@rpcincl.example.org", "Live Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	dead, err := s.PreCreateLocalUser(ctx, "rpcdead", "dead@rpcincl.example.org", "Deleted Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser dead: %v", err)
	}
	if _, err := s.DeleteUser(ctx, dead.ID, nil, "test"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// Default: the typeahead's behaviour, unchanged.
	def, err := h.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: "rpcincl.example.org", Limit: 50,
	})
	if err != nil {
		t.Fatalf("ListUsersByEmail default: %v", err)
	}
	if len(def.GetUsers()) != 1 {
		t.Fatalf("default must return only the live user, got %d", len(def.GetUsers()))
	}
	if def.GetUsers()[0].GetId() != live.ID.String() {
		t.Fatalf("default returned %s, want the live user %s", def.GetUsers()[0].GetId(), live.ID)
	}
	if got := def.GetUsers()[0].GetDeletedAt(); got != "" {
		t.Errorf("a live user must have an empty deleted_at, got %q", got)
	}

	// Opt-in: the admin directory's behaviour.
	incl, err := h.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: "rpcincl.example.org", Limit: 50, IncludeDeleted: true,
	})
	if err != nil {
		t.Fatalf("ListUsersByEmail include_deleted: %v", err)
	}
	if len(incl.GetUsers()) != 2 {
		t.Fatalf("include_deleted must return both users, got %d", len(incl.GetUsers()))
	}
	var found *identityv1.User
	for _, u := range incl.GetUsers() {
		if u.GetId() == dead.ID.String() {
			found = u
		}
	}
	if found == nil {
		t.Fatalf("include_deleted did not return the soft-deleted user %s", dead.ID)
	}
	if found.GetDeletedAt() == "" {
		t.Errorf("a tombstoned user must carry deleted_at so the admin list can mark it closed")
	}
	if found.GetEmail() != "dead@rpcincl.example.org" {
		t.Errorf("tombstoned user lost its email: %q", found.GetEmail())
	}
	// Deleted outright rather than merged, so there is no trail to follow.
	if found.GetMergedIntoUserId() != "" {
		t.Errorf("a delete-outright tombstone must have no merged_into_user_id, got %q", found.GetMergedIntoUserId())
	}
}
