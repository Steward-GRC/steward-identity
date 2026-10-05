// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// uuidNil avoids leaking uuid into the import list of read_test.go indirectly.
func uuidNil() uuid.UUID { return uuid.Nil }

// adminCtx returns a context whose forwarded actor is userID, holding
// site-admin.
func adminCtx(userID string) context.Context {
	return claimsCtx(userID, []string{"site-admin"})
}

// noopCtx returns a context with no claims and no TLS — used to assert that
// admin RPCs are PermissionDenied for unauthenticated callers.
func noopCtx() context.Context { return context.Background() }

func TestAdminGrantRoleRequiresAuth(t *testing.T) {
	s := newTestStore(t)
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	_, err := h.GrantRole(noopCtx(), &identityv1.GrantRoleRequest{UserId: uuid.New().String(), Role: "author"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestAdminGrantRoleWithAdminClaim(t *testing.T) {
	s := newTestStore(t)
	// Seed an admin user (the actor) and a target user.
	admin, err := s.JITProvision(context.Background(), "kc-admin-actor", "a@e", "A")
	if err != nil {
		t.Fatalf("JIT admin: %v", err)
	}
	u, err := s.JITProvision(context.Background(), "kc-admin-test", "u@e", "U")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	resp, err := h.GrantRole(adminCtx(admin.ID.String()),
		&identityv1.GrantRoleRequest{UserId: u.ID.String(), Role: "author", Category: "IT Security"})
	if err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	hasAuthor := false
	for _, sr := range resp.User.ScopedRoles {
		if sr.Role == "author" && sr.Category == "IT Security" {
			hasAuthor = true
		}
	}
	if !hasAuthor {
		t.Fatalf("expected author/IT Security in ScopedRoles, got %v", resp.User.ScopedRoles)
	}
}

func TestAdminCreateGroup(t *testing.T) {
	s := newTestStore(t)
	admin, err := s.JITProvision(context.Background(), "kc-cg-actor", "cg@e", "CG")
	if err != nil {
		t.Fatalf("JIT actor: %v", err)
	}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	resp, err := h.CreateGroup(adminCtx(admin.ID.String()),
		&identityv1.CreateGroupRequest{Name: "Eng"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if resp.Group.Name != "Eng" {
		t.Fatalf("name: %q", resp.Group.Name)
	}
}

func TestAdminGrantScopedRoleProjectsScopedRoles(t *testing.T) {
	s := newTestStore(t)
	admin, err := s.JITProvision(context.Background(), "kc-sr-actor", "sra@e", "SrA")
	if err != nil {
		t.Fatalf("JIT admin: %v", err)
	}
	target, err := s.JITProvision(context.Background(), "kc-sr-target", "srt@e", "SrT")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	resp, err := h.GrantRole(adminCtx(admin.ID.String()),
		&identityv1.GrantRoleRequest{UserId: target.ID.String(), Role: "author", Category: "Finance"})
	if err != nil {
		t.Fatalf("GrantRole scoped: %v", err)
	}
	found := false
	for _, sr := range resp.User.ScopedRoles {
		if sr.Role == "author" && sr.Category == "Finance" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ScopedRoles to contain author/Finance, got %v", resp.User.ScopedRoles)
	}
}

func TestAdminGrantAdminRoleWithCategoryInvalidArgument(t *testing.T) {
	s := newTestStore(t)
	admin, err := s.JITProvision(context.Background(), "kc-cat-actor", "cata@e", "CatA")
	if err != nil {
		t.Fatalf("JIT admin: %v", err)
	}
	target, err := s.JITProvision(context.Background(), "kc-cat-target", "catt@e", "CatT")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	// A global role must not have a category; expect InvalidArgument from the store validator.
	_, err = h.GrantRole(adminCtx(admin.ID.String()),
		&identityv1.GrantRoleRequest{UserId: target.ID.String(), Role: "site-admin", Category: "SomeCategory"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for site-admin+category, got %v", err)
	}
}

func TestAdminSetUserPolicyOverrideAllowThenClear(t *testing.T) {
	s := newTestStore(t)
	admin, err := s.JITProvision(context.Background(), "kc-ov-actor", "ova@e", "OvA")
	if err != nil {
		t.Fatalf("JIT admin: %v", err)
	}
	target, err := s.JITProvision(context.Background(), "kc-ov-target", "ovt@e", "OvT")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	ctx := adminCtx(admin.ID.String())

	// Set allow override.
	respAllow, err := h.SetUserPolicyOverride(ctx, &identityv1.SetUserPolicyOverrideRequest{
		UserId:       target.ID.String(),
		PolicyNumber: "POL-001",
		Effect:       identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW,
	})
	if err != nil {
		t.Fatalf("SetUserPolicyOverride allow: %v", err)
	}
	foundAllow := false
	for _, ov := range respAllow.User.PolicyOverrides {
		if ov.PolicyNumber == "POL-001" && ov.Effect == identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW {
			foundAllow = true
		}
	}
	if !foundAllow {
		t.Fatalf("expected POL-001/allow override, got %v", respAllow.User.PolicyOverrides)
	}

	// Clear with UNSPECIFIED.
	respClear, err := h.SetUserPolicyOverride(ctx, &identityv1.SetUserPolicyOverrideRequest{
		UserId:       target.ID.String(),
		PolicyNumber: "POL-001",
		Effect:       identityv1.OverrideEffect_OVERRIDE_EFFECT_UNSPECIFIED,
	})
	if err != nil {
		t.Fatalf("SetUserPolicyOverride clear: %v", err)
	}
	for _, ov := range respClear.User.PolicyOverrides {
		if ov.PolicyNumber == "POL-001" {
			t.Fatalf("expected POL-001 override cleared, still present: %v", respClear.User.PolicyOverrides)
		}
	}
}

func TestAdminNewRPCsRequireAuth(t *testing.T) {
	s := newTestStore(t)
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)

	_, err := h.SetUserPolicyOverride(noopCtx(), &identityv1.SetUserPolicyOverrideRequest{
		UserId:       uuid.New().String(),
		PolicyNumber: "POL-X",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("SetUserPolicyOverride: expected PermissionDenied, got %v", err)
	}
}

func TestDisableUserRevokesSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, _ := s.JITProvision(ctx, "sub-d", "d@e", "D")
	fk := newFakeKratos()
	fk.addWithID("sub-d", kratos.Account{Email: "d@e"})
	fk.addSession("sub-d", true)
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)
	if _, err := h.DisableUser(adminCtx(u.ID.String()), &identityv1.DisableUserRequest{UserId: u.ID.String()}); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	if fk.sessions["sub-d"][0].Active {
		t.Fatal("disabled user's session must be revoked")
	}
}

func TestAdminBootstrapInitialAdmin(t *testing.T) {
	s := newTestStore(t)
	auth := testAdminAuth()
	h := handlers.NewAdminHandler(s, auth)
	// First bootstrap: there's no admin yet, so this MUST come from the
	// admin CLI path. The admin-claim path here would PermissionDenied because
	// no role-bearing user exists. We test the admin CLI path indirectly by
	// pre-seeding an admin via the store, then verifying the idempotent
	// no-op behavior via the handler.
	seed, err := s.JITProvision(context.Background(), "kc-pre-admin", "pre@e", "Pre")
	if err != nil {
		t.Fatalf("JIT seed: %v", err)
	}
	if _, _, err := s.BootstrapAdmin(context.Background(), seed.ExternalSubject, seed.Email, "test-bootstrap"); err != nil {
		t.Fatalf("BootstrapAdmin seed: %v", err)
	}
	resp, err := h.BootstrapInitialAdmin(adminCtx(seed.ID.String()),
		&identityv1.BootstrapInitialAdminRequest{ExternalSubject: "kc-other", Email: "other@e"})
	if err != nil {
		t.Fatalf("BootstrapInitialAdmin (idempotent): %v", err)
	}
	if resp.Created {
		t.Fatal("expected created=false on idempotent call")
	}
}
