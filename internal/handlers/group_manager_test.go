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

// TestGrantRevokeGroupManager covers the admin RPCs and the managed_group_ids
// projection they drive. Only a site-admin may grant.
func TestGrantRevokeGroupManager(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-gm-admin", "gmadmin@e", "A")
	user, _ := s.JITProvision(ctx, "kc-gm-user", "gmuser@e", "U")
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	adm := adminCtx(admin.ID.String())

	g, _ := h.CreateGroup(adm, &identityv1.CreateGroupRequest{Name: "Team"})

	grant, err := h.GrantGroupManager(adm, &identityv1.GrantGroupManagerRequest{
		UserId: user.ID.String(), GroupId: g.Group.Id,
	})
	if err != nil {
		t.Fatalf("GrantGroupManager: %v", err)
	}
	if len(grant.User.ManagedGroupIds) != 1 || grant.User.ManagedGroupIds[0] != g.Group.Id {
		t.Fatalf("managed_group_ids=%v", grant.User.ManagedGroupIds)
	}

	// A non-site-admin cannot grant the manager role.
	if _, err := h.GrantGroupManager(claimsCtx(user.ID.String(), nil), &identityv1.GrantGroupManagerRequest{
		UserId: user.ID.String(), GroupId: g.Group.Id,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin grant must be denied, got %v", err)
	}

	rev, err := h.RevokeGroupManager(adm, &identityv1.RevokeGroupManagerRequest{
		UserId: user.ID.String(), GroupId: g.Group.Id,
	})
	if err != nil {
		t.Fatalf("RevokeGroupManager: %v", err)
	}
	if len(rev.User.ManagedGroupIds) != 0 {
		t.Fatalf("expected no managed groups after revoke, got %v", rev.User.ManagedGroupIds)
	}
}

// TestGroupManagerScopedMembership covers the scoped membership authz on the
// admin RPCs: a group-manager may add/remove MANUAL members of
// their group, is refused on IdP-synced rows, and is denied entirely on groups
// they do not manage.
func TestGroupManagerScopedMembership(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-sc-admin", "scadmin@e", "A")
	mgr, _ := s.JITProvision(ctx, "kc-sc-mgr", "scmgr@e", "M")
	target, _ := s.JITProvision(ctx, "kc-sc-tgt", "sctgt@e", "T")
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	adm := adminCtx(admin.ID.String())

	mine, _ := h.CreateGroup(adm, &identityv1.CreateGroupRequest{Name: "Mine"})
	other, _ := h.CreateGroup(adm, &identityv1.CreateGroupRequest{Name: "Other"})

	if err := s.GrantGroupManager(ctx, mgr.ID, uuid.MustParse(mine.Group.Id), nil, "test"); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	mgrCtx := claimsCtx(mgr.ID.String(), nil) // NOT a site-admin

	// Manager can add a member to their own group (manual provenance).
	if _, err := h.AddUserToGroup(mgrCtx, &identityv1.AddUserToGroupRequest{
		UserId: target.ID.String(), GroupId: mine.Group.Id,
	}); err != nil {
		t.Fatalf("manager add to own group: %v", err)
	}
	// ...and remove it again.
	if _, err := h.RemoveUserFromGroup(mgrCtx, &identityv1.RemoveUserFromGroupRequest{
		UserId: target.ID.String(), GroupId: mine.Group.Id,
	}); err != nil {
		t.Fatalf("manager remove from own group: %v", err)
	}

	// Manager is denied on a group they don't manage.
	if _, err := h.AddUserToGroup(mgrCtx, &identityv1.AddUserToGroupRequest{
		UserId: target.ID.String(), GroupId: other.Group.Id,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("manager add to unmanaged group must be denied, got %v", err)
	}

	// Seed a sync-owned membership in the managed group; the manager cannot
	// remove it, but a site-admin can.
	if _, err := s.AddUserToGroup(ctx, target.ID, uuid.MustParse(mine.Group.Id), nil, "sso-jit", "idp-sync"); err != nil {
		t.Fatalf("seed sync membership: %v", err)
	}
	if _, err := h.RemoveUserFromGroup(mgrCtx, &identityv1.RemoveUserFromGroupRequest{
		UserId: target.ID.String(), GroupId: mine.Group.Id,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("manager remove of sync-owned row must be denied, got %v", err)
	}
	if _, err := h.RemoveUserFromGroup(adm, &identityv1.RemoveUserFromGroupRequest{
		UserId: target.ID.String(), GroupId: mine.Group.Id,
	}); err != nil {
		t.Fatalf("site-admin remove of sync-owned row: %v", err)
	}
}
