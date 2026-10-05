// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGrantPermission_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewAdminHandler(s, testAdminAuth())
	_, err := h.GrantPermission(noopCtx(),
		&identityv1.GrantPermissionRequest{UserId: uuidNil().String(), Permission: "policy.read_sensitive"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestGrantPermission_NonRootDenied(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// A site-admin actor that is NOT root.
	actor, err := s.JITProvision(ctx, "kc-nonroot-actor", "nra@e", "NRA")
	if err != nil {
		t.Fatalf("JIT actor: %v", err)
	}
	if _, err := s.GrantRole(ctx, actor.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("grant site-admin: %v", err)
	}
	target, err := s.JITProvision(ctx, "kc-perm-target", "pt@e", "PT")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())
	_, err = h.GrantPermission(adminCtx(actor.ID.String()),
		&identityv1.GrantPermissionRequest{UserId: target.ID.String(), Permission: "policy.read_sensitive"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for non-root actor, got %v", err)
	}
}

func TestGrantPermission_RootGrants(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Seed the protected root account (is_root + site-admin).
	rootSeed, err := s.JITProvision(ctx, "kc-root-actor", "root@e", "Root")
	if err != nil {
		t.Fatalf("JIT root: %v", err)
	}
	if _, _, err := s.BootstrapAdmin(ctx, rootSeed.ExternalSubject, rootSeed.Email, "test-bootstrap"); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	target, err := s.JITProvision(ctx, "kc-perm-target2", "pt2@e", "PT2")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())
	resp, err := h.GrantPermission(adminCtx(rootSeed.ID.String()),
		&identityv1.GrantPermissionRequest{UserId: target.ID.String(), Permission: "policy.read_sensitive"})
	if err != nil {
		t.Fatalf("GrantPermission by root: %v", err)
	}
	if !resp.GetUser().GetReadSensitiveGrant() {
		t.Fatal("expected read_sensitive_grant true on returned user")
	}

	// Revoke (root) clears it.
	resp2, err := h.RevokePermission(adminCtx(rootSeed.ID.String()),
		&identityv1.RevokePermissionRequest{UserId: target.ID.String(), Permission: "policy.read_sensitive"})
	if err != nil {
		t.Fatalf("RevokePermission by root: %v", err)
	}
	if resp2.GetUser().GetReadSensitiveGrant() {
		t.Fatal("expected read_sensitive_grant false after revoke")
	}
}
