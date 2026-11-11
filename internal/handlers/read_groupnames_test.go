// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"slices"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// TestReadListUserGroupNames checks the batch the gateway fills the ack roster
// from: one entry per requested id, in request order, each with the user's
// direct group names in a stable order, and an empty list for a user with no
// groups or an id nobody has.
func TestReadListUserGroupNames(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	u1, err := s.JITProvision(ctx, "kc-gn-1", "gn1@e", "GN1")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := s.JITProvision(ctx, "kc-gn-2", "gn2@e", "GN2")
	if err != nil {
		t.Fatal(err)
	}
	finance, _ := s.CreateGroup(ctx, "Finance team", uuid.Nil, nil, nil, "tester")
	approvers, _ := s.CreateGroup(ctx, "Approvers", uuid.Nil, nil, nil, "tester")
	for _, g := range []uuid.UUID{finance.ID, approvers.ID} {
		if _, err := s.AddUserToGroup(ctx, u1.ID, g, nil, "t", "manual"); err != nil {
			t.Fatal(err)
		}
	}
	unknown := uuid.NewString()

	h := handlers.NewReadHandler(s)
	resp, err := h.ListUserGroupNames(ctx, &identityv1.ListUserGroupNamesRequest{
		UserIds: []string{u2.ID.String(), u1.ID.String(), unknown},
	})
	if err != nil {
		t.Fatalf("ListUserGroupNames: %v", err)
	}
	if len(resp.GetUsers()) != 3 {
		t.Fatalf("got %d entries, want 3", len(resp.GetUsers()))
	}
	order := []string{u2.ID.String(), u1.ID.String(), unknown}
	for i, id := range order {
		if resp.GetUsers()[i].GetUserId() != id {
			t.Fatalf("entry %d is %s, want %s (request order)", i, resp.GetUsers()[i].GetUserId(), id)
		}
	}
	if len(resp.GetUsers()[0].GetGroupNames()) != 0 {
		t.Fatalf("user with no groups = %v", resp.GetUsers()[0].GetGroupNames())
	}
	if want := []string{"Approvers", "Finance team"}; !slices.Equal(resp.GetUsers()[1].GetGroupNames(), want) {
		t.Fatalf("groups = %v, want %v", resp.GetUsers()[1].GetGroupNames(), want)
	}
	if len(resp.GetUsers()[2].GetGroupNames()) != 0 {
		t.Fatalf("unknown id = %v, want none", resp.GetUsers()[2].GetGroupNames())
	}
}

func TestReadListUserGroupNamesRefusesBadInput(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := handlers.NewReadHandler(s)

	resp, err := h.ListUserGroupNames(ctx, &identityv1.ListUserGroupNamesRequest{})
	if err != nil || len(resp.GetUsers()) != 0 {
		t.Fatalf("no ids: %v, %v", resp, err)
	}
	_, err = h.ListUserGroupNames(ctx, &identityv1.ListUserGroupNamesRequest{UserIds: []string{"not-a-uuid"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad id: %v, want InvalidArgument", err)
	}
	ids := make([]string, 0, 1001)
	for i := 0; i < 1001; i++ {
		ids = append(ids, uuid.NewString())
	}
	_, err = h.ListUserGroupNames(ctx, &identityv1.ListUserGroupNamesRequest{UserIds: ids})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("%d ids: %v, want InvalidArgument", len(ids), err)
	}
}
