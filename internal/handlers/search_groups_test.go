// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

func TestSearchGroups_FindsByNameAndRefusesAnOpenSweep(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, n := range []string{"Risk Committee", "Audit Committee", "Facilities"} {
		if _, err := s.CreateGroup(ctx, n, uuid.Nil, nil, nil, "test"); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	h := handlers.NewReadHandler(s)

	resp, err := h.SearchGroups(ctx, &identityv1.SearchGroupsRequest{Query: " committee "})
	if err != nil {
		t.Fatalf("SearchGroups: %v", err)
	}
	if len(resp.GetGroups()) != 2 || resp.GetGroups()[0].GetName() != "Audit Committee" || resp.GetGroups()[1].GetName() != "Risk Committee" {
		t.Fatalf("groups: %v", resp.GetGroups())
	}
	if resp.GetGroups()[0].GetId() == "" {
		t.Fatal("a group came back with no id")
	}

	for _, q := range []string{"", "   "} {
		if _, err := h.SearchGroups(ctx, &identityv1.SearchGroupsRequest{Query: q}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("query %q: want InvalidArgument, got %v", q, err)
		}
	}
}

func TestSearchGroups_CapsTheLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, n := range []string{"Lim 1", "Lim 2", "Lim 3"} {
		if _, err := s.CreateGroup(ctx, n, uuid.Nil, nil, nil, "test"); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	h := handlers.NewReadHandler(s)
	resp, err := h.SearchGroups(ctx, &identityv1.SearchGroupsRequest{Query: "lim", Limit: 2})
	if err != nil || len(resp.GetGroups()) != 2 {
		t.Fatalf("limit 2: got %d (%v)", len(resp.GetGroups()), err)
	}
}
