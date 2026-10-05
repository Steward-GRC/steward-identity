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

// TestMarkEmailVerified_VerifiesThenIdempotent covers the happy path (first
// call marks verified, already_verified=false) and the idempotent replay (a
// second call for the same address succeeds with already_verified=true).
func TestMarkEmailVerified_VerifiesThenIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "kc-ev-1", "ev1@example.com", "Ev One")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewReadHandler(s)

	resp, err := h.MarkEmailVerified(ctx, &identityv1.MarkEmailVerifiedRequest{
		UserId: u.ID.String(), Email: "ev1@example.com",
	})
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if resp.GetAlreadyVerified() {
		t.Fatal("first verify: expected already_verified=false")
	}

	// Idempotent replay (case-insensitive match) — no error, already_verified=true.
	resp, err = h.MarkEmailVerified(ctx, &identityv1.MarkEmailVerifiedRequest{
		UserId: u.ID.String(), Email: "EV1@Example.com",
	})
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	if !resp.GetAlreadyVerified() {
		t.Fatal("second verify: expected already_verified=true")
	}
}

// TestMarkEmailVerified_EmailMismatch rejects a token minted for an address the
// account no longer uses (FailedPrecondition).
func TestMarkEmailVerified_EmailMismatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "kc-ev-2", "ev2@example.com", "Ev Two")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewReadHandler(s)

	_, err = h.MarkEmailVerified(ctx, &identityv1.MarkEmailVerifiedRequest{
		UserId: u.ID.String(), Email: "old-address@example.com",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition on email mismatch, got %v", err)
	}
}

// TestMarkEmailVerified_UnknownUser maps a missing user to NotFound.
func TestMarkEmailVerified_UnknownUser(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewReadHandler(s)
	_, err := h.MarkEmailVerified(context.Background(), &identityv1.MarkEmailVerifiedRequest{
		UserId: "11111111-1111-1111-1111-111111111111", Email: "nobody@example.com",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for unknown user, got %v", err)
	}
}

// TestMarkEmailVerified_BadInput rejects a malformed user_id and an empty email
// before any store call (InvalidArgument).
func TestMarkEmailVerified_BadInput(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewReadHandler(s)
	if _, err := h.MarkEmailVerified(context.Background(), &identityv1.MarkEmailVerifiedRequest{
		UserId: "not-a-uuid", Email: "x@example.com",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for bad user_id, got %v", err)
	}
	if _, err := h.MarkEmailVerified(context.Background(), &identityv1.MarkEmailVerifiedRequest{
		UserId: "11111111-1111-1111-1111-111111111111", Email: "   ",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for empty email, got %v", err)
	}
}
