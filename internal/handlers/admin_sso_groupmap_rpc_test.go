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
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestGroupMappingRPCs_AddListDelete is the Task-15-follow-on wiring test: the
// group-mapping admin RPCs must actually reach the (already-implemented)
// store CRUD instead of falling through to UnimplementedIdentitySSOAdminServiceServer.
// AddGroupMapping creates a mapping for a real connection + group,
// ListGroupMappings must round-trip target_group_id, and DeleteGroupMapping
// must remove it.
func TestGroupMappingRPCs_AddListDelete(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Partner Organisation", Protocol: "oidc", ConnectionAlias: "partner"})
	if err != nil {
		t.Fatalf("CreateIdPConnection: %v", err)
	}
	g, err := s.CreateGroup(ctx, "Engineering", uuid.Nil, nil, nil, "test")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	authed := adminCtx(uuid.NewString())

	addResp, err := h.AddGroupMapping(authed, &identityv1.AddGroupMappingRequest{
		ConnectionId:       conn.ID.String(),
		IdpGroupClaimValue: "eng",
		TargetGroupId:      g.ID.String(),
	})
	if err != nil {
		t.Fatalf("AddGroupMapping: %v", err)
	}
	m := addResp.GetMapping()
	if m == nil {
		t.Fatal("expected non-nil mapping")
	}
	if m.GetId() == "" {
		t.Fatal("expected a generated mapping id")
	}
	if m.GetConnectionId() != conn.ID.String() {
		t.Fatalf("connection_id: got %q want %q", m.GetConnectionId(), conn.ID.String())
	}
	if m.GetIdpGroupClaimValue() != "eng" {
		t.Fatalf("idp_group_claim_value: got %q", m.GetIdpGroupClaimValue())
	}
	if m.GetTargetGroupId() != g.ID.String() {
		t.Fatalf("target_group_id: got %q want %q", m.GetTargetGroupId(), g.ID.String())
	}

	listResp, err := h.ListGroupMappings(authed, &identityv1.ListGroupMappingsRequest{ConnectionId: conn.ID.String()})
	if err != nil {
		t.Fatalf("ListGroupMappings: %v", err)
	}
	if len(listResp.GetMappings()) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(listResp.GetMappings()))
	}
	if listResp.GetMappings()[0].GetTargetGroupId() != g.ID.String() {
		t.Fatalf("target_group_id did not round-trip through List: got %q want %q",
			listResp.GetMappings()[0].GetTargetGroupId(), g.ID.String())
	}

	if _, err := h.DeleteGroupMapping(authed, &identityv1.DeleteGroupMappingRequest{MappingId: m.GetId()}); err != nil {
		t.Fatalf("DeleteGroupMapping: %v", err)
	}

	listAfter, err := h.ListGroupMappings(authed, &identityv1.ListGroupMappingsRequest{ConnectionId: conn.ID.String()})
	if err != nil {
		t.Fatalf("ListGroupMappings after delete: %v", err)
	}
	if len(listAfter.GetMappings()) != 0 {
		t.Fatalf("expected 0 mappings after delete, got %d", len(listAfter.GetMappings()))
	}
}

// TestGroupMappingRPCs_RequireAuth verifies all three RPCs are Authorize-gated
// — an unauthenticated caller must be rejected before any store work, not
// fall through to the Unimplemented base (which would return Unimplemented,
// not PermissionDenied).
func TestGroupMappingRPCs_RequireAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	unauthed := noopCtx()

	if _, err := h.AddGroupMapping(unauthed, &identityv1.AddGroupMappingRequest{
		ConnectionId: uuid.NewString(), IdpGroupClaimValue: "eng", TargetGroupId: uuid.NewString(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AddGroupMapping: expected PermissionDenied, got %v", err)
	}
	if _, err := h.ListGroupMappings(unauthed, &identityv1.ListGroupMappingsRequest{
		ConnectionId: uuid.NewString(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ListGroupMappings: expected PermissionDenied, got %v", err)
	}
	if _, err := h.DeleteGroupMapping(unauthed, &identityv1.DeleteGroupMappingRequest{
		MappingId: uuid.NewString(),
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("DeleteGroupMapping: expected PermissionDenied, got %v", err)
	}
}
