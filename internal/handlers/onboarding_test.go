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

func TestCompleteOnboarding_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewAdminHandler(s, testAdminAuth())
	_, err := h.CompleteOnboarding(noopCtx(), &identityv1.CompleteOnboardingRequest{AcceptTerms: true})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without claims, got %v", err)
	}
}

func TestCompleteOnboarding_RequiresAcceptTerms(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "kc-onb-1", "onb1@example.com", "Onb One")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())
	// A plain authenticated user (no roles) — proves this is NOT admin-gated.
	_, err = h.CompleteOnboarding(claimsCtx(u.ID.String(), nil),
		&identityv1.CompleteOnboardingRequest{AcceptTerms: false})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument when accept_terms=false, got %v", err)
	}
}

func TestCompleteOnboarding_NonAdminSucceeds(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "kc-onb-2", "onb2@example.com", "Onb Two")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	if u.OnboardingComplete {
		t.Fatal("precondition: new user must be un-onboarded")
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	resp, err := h.CompleteOnboarding(claimsCtx(u.ID.String(), nil),
		&identityv1.CompleteOnboardingRequest{
			AcceptTerms: true,
			FirstName:   new("Onboarded"),
			LastName:    new("Two"),
			Username:    new("onbtwo"),
		})
	if err != nil {
		t.Fatalf("CompleteOnboarding: %v", err)
	}
	got := resp.GetUser()
	if got.GetNeedsOnboarding() {
		t.Fatal("expected needs_onboarding=false after completion")
	}
	// Display name is derived from first+last.
	if got.GetName() != "Onboarded Two" {
		t.Fatalf("derived name: got %q want %q", got.GetName(), "Onboarded Two")
	}
	if got.GetFirstName() != "Onboarded" || got.GetLastName() != "Two" {
		t.Fatalf("first/last: got %q/%q", got.GetFirstName(), got.GetLastName())
	}
	if got.GetUsername() != "onbtwo" {
		t.Fatalf("username: got %q", got.GetUsername())
	}
}

// TestCompleteOnboarding_PersistsFirstLastEmail verifies the editable /welcome
// fields (first/last name + email) are persisted, and that `name` is composed
// from the structured parts when no explicit display name was supplied.
func TestCompleteOnboarding_PersistsFirstLastEmail(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// JIT with no structured names — the /welcome fields start empty/editable.
	u, err := s.JITProvision(ctx, "kc-onb-3", "onb3@example.com", "Onb Three")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	resp, err := h.CompleteOnboarding(claimsCtx(u.ID.String(), nil),
		&identityv1.CompleteOnboardingRequest{
			AcceptTerms: true,
			FirstName:   new("Onb"),
			LastName:    new("Third"),
			Email:       new("onb.third@example.com"),
		})
	if err != nil {
		t.Fatalf("CompleteOnboarding: %v", err)
	}
	got := resp.GetUser()
	if got.GetFirstName() != "Onb" || got.GetLastName() != "Third" {
		t.Fatalf("first/last: got %q/%q", got.GetFirstName(), got.GetLastName())
	}
	if got.GetEmail() != "onb.third@example.com" {
		t.Fatalf("email: got %q", got.GetEmail())
	}
	// No explicit display name in the request -> composed from the parts.
	if got.GetName() != "Onb Third" {
		t.Fatalf("composed name: got %q want %q", got.GetName(), "Onb Third")
	}
	if got.GetNeedsOnboarding() {
		t.Fatal("expected needs_onboarding=false after completion")
	}
}
