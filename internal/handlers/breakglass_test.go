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

func TestBreakGlassReveal_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewAdminHandler(s, testAdminAuth())
	_, err := h.BreakGlassReveal(noopCtx(),
		&identityv1.BreakGlassRevealRequest{PolicyNumber: "POL-IT-1", Reason: "incident"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestBreakGlassReveal_EmptyReason(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	actor, err := s.JITProvision(ctx, "kc-bg-actor", "bga@e", "BGA")
	if err != nil {
		t.Fatalf("JIT actor: %v", err)
	}
	if _, err := s.GrantRole(ctx, actor.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("grant site-admin: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())
	_, err = h.BreakGlassReveal(adminCtx(actor.ID.String()),
		&identityv1.BreakGlassRevealRequest{PolicyNumber: "POL-IT-1", Reason: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty reason, got %v", err)
	}
}

func TestBreakGlassReveal_GrantsAndActive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	actor, err := s.JITProvision(ctx, "kc-bg-actor2", "bga2@e", "BGA2")
	if err != nil {
		t.Fatalf("JIT actor: %v", err)
	}
	if _, err := s.GrantRole(ctx, actor.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("grant site-admin: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	resp, err := h.BreakGlassReveal(adminCtx(actor.ID.String()),
		&identityv1.BreakGlassRevealRequest{PolicyNumber: "POL-IT-1", Reason: "investigating"})
	if err != nil {
		t.Fatalf("BreakGlassReveal: %v", err)
	}
	if resp.GetGrantedUntil() == "" {
		t.Fatal("expected non-empty granted_until")
	}

	active, err := h.ActiveBreakGlass(adminCtx(actor.ID.String()), &identityv1.ActiveBreakGlassRequest{})
	if err != nil {
		t.Fatalf("ActiveBreakGlass: %v", err)
	}
	if len(active.GetPolicyNumbers()) != 1 || active.GetPolicyNumbers()[0] != "POL-IT-1" {
		t.Fatalf("active: %v", active.GetPolicyNumbers())
	}
}
