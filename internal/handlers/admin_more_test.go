// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

func TestAdminEnableDisableUser(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-ed", "ed@e", "Ed")
	target, _ := s.JITProvision(context.Background(), "kc-tgt", "tgt@e", "Tgt")

	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	ctx := adminCtx(admin.ID.String())

	dis, err := h.DisableUser(ctx, &identityv1.DisableUserRequest{UserId: target.ID.String()})
	if err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if dis.User.Enabled {
		t.Fatal("expected disabled")
	}
	en, err := h.EnableUser(ctx, &identityv1.EnableUserRequest{UserId: target.ID.String()})
	if err != nil {
		t.Fatalf("EnableUser: %v", err)
	}
	if !en.User.Enabled {
		t.Fatal("expected enabled")
	}
}

func TestAdminRenameAndDeleteGroup(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-rd", "rd@e", "Rd")
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	ctx := adminCtx(admin.ID.String())

	create, err := h.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "Original"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	rn, err := h.RenameGroup(ctx, &identityv1.RenameGroupRequest{GroupId: create.Group.Id, NewName: "Renamed"})
	if err != nil {
		t.Fatalf("RenameGroup: %v", err)
	}
	if rn.Group.Name != "Renamed" {
		t.Fatalf("rename: %q", rn.Group.Name)
	}
	if _, err := h.DeleteGroup(ctx, &identityv1.DeleteGroupRequest{GroupId: create.Group.Id}); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
}

func TestAdminMembershipFlow(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-mb", "mb@e", "Mb")
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	ctx := adminCtx(admin.ID.String())

	g, _ := h.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "Team"})
	target, _ := s.JITProvision(context.Background(), "kc-mb-t", "t@e", "T")

	if _, err := h.AddUserToGroup(ctx, &identityv1.AddUserToGroupRequest{
		UserId: target.ID.String(), GroupId: g.Group.Id,
	}); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}
	if _, err := h.RemoveUserFromGroup(ctx, &identityv1.RemoveUserFromGroupRequest{
		UserId: target.ID.String(), GroupId: g.Group.Id,
	}); err != nil {
		t.Fatalf("RemoveUserFromGroup: %v", err)
	}
}

func TestAdminSetGroupParent(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-sp", "sp@e", "Sp")
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	ctx := adminCtx(admin.ID.String())

	parent, _ := h.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "P"})
	child, _ := h.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "C"})

	got, err := h.SetGroupParent(ctx, &identityv1.SetGroupParentRequest{
		GroupId: child.Group.Id, NewParentId: parent.Group.Id,
	})
	if err != nil {
		t.Fatalf("SetGroupParent: %v", err)
	}
	if got.Group.ParentId != parent.Group.Id {
		t.Fatalf("parent: got %s want %s", got.Group.ParentId, parent.Group.Id)
	}
}

func TestAdminRevokeRole(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-rv", "rv@e", "Rv")
	target, _ := s.JITProvision(context.Background(), "kc-rv-t", "rvt@e", "RvT")
	if _, err := s.GrantRole(context.Background(), target.ID, "author", "IT Security", &admin.ID, "tester"); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	resp, err := h.RevokeRole(adminCtx(admin.ID.String()),
		&identityv1.RevokeRoleRequest{UserId: target.ID.String(), Role: "author", Category: "IT Security"})
	if err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}
	// author/IT Security is scoped, so it appears in ScopedRoles not Roles.
	for _, sr := range resp.User.ScopedRoles {
		if sr.Role == "author" && sr.Category == "IT Security" {
			t.Fatalf("expected author/IT Security absent from scoped roles, got %v", resp.User.ScopedRoles)
		}
	}
}

func TestAdminInputValidation(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-iv", "iv@e", "Iv")
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	ctx := adminCtx(admin.ID.String())

	// Missing user_id.
	if _, err := h.EnableUser(ctx, &identityv1.EnableUserRequest{}); err == nil {
		t.Fatal("expected error for missing user_id")
	}
	// Bad UUID.
	if _, err := h.GrantRole(ctx, &identityv1.GrantRoleRequest{UserId: "not-a-uuid", Role: "author"}); err == nil {
		t.Fatal("expected error for malformed user_id")
	}
	// Missing role.
	if _, err := h.GrantRole(ctx, &identityv1.GrantRoleRequest{UserId: uuid.New().String()}); err == nil {
		t.Fatal("expected error for missing role")
	}
	// Missing group name.
	if _, err := h.CreateGroup(ctx, &identityv1.CreateGroupRequest{}); err == nil {
		t.Fatal("expected error for missing name")
	}
}
