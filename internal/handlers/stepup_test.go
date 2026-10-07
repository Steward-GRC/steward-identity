// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// fakeSender captures the last email sent so tests can pull the step-up code out
// of the dev-echo/store instead of parsing mail. It implements email.Sender.
type fakeSender struct {
	mu      sync.Mutex
	to      string
	subject string
	body    string
	sent    int
}

func (f *fakeSender) Send(_ context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.to, f.subject, f.body = to, subject, body
	f.sent++
	return nil
}

// stepUpCodeFor mints a step_up OTP for the given user via the store, exactly as
// RequestStepUpOtp does internally, returning the plaintext so the root admin
// tests can pass a genuinely-valid code without scraping mail. Kept separate
// from the RequestStepUpOtp path so the "mints + emails" test stays honest.
func stepUpCodeFor(t *testing.T, s *store.Store, userID string) string {
	t.Helper()
	uid, err := uuid.Parse(userID)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	code, err := s.GenerateOTP(context.Background(), uid, store.OTPPurposeStepUp)
	if err != nil {
		t.Fatalf("mint step_up otp: %v", err)
	}
	return code
}

// TestRequestStepUpOtpMintsAndEmails verifies the request flow emails a code to
// the acting admin's own address with the root-change subject.
func TestRequestStepUpOtpMintsAndEmails(t *testing.T) {
	s := newTestStore(t)
	admin, err := s.JITProvision(context.Background(), "kc-stepup-actor", "actor@example.example.org", "Actor")
	if err != nil {
		t.Fatalf("JIT admin: %v", err)
	}
	sender := &fakeSender{}
	h := handlers.NewAdminHandler(s, testAdminAuth()).
		WithOTP(sender, zerolog.Nop(), true)

	if _, err := h.RequestStepUpOtp(adminCtx(admin.ID.String()), &identityv1.RequestStepUpOtpRequest{}); err != nil {
		t.Fatalf("RequestStepUpOtp: %v", err)
	}
	if sender.sent != 1 {
		t.Fatalf("want 1 email sent, got %d", sender.sent)
	}
	if sender.to != "actor@example.example.org" {
		t.Fatalf("email sent to %q, want actor@example.example.org", sender.to)
	}
	if sender.subject != "Your confirmation code for a root admin change" {
		t.Fatalf("unexpected subject %q", sender.subject)
	}
}

// TestRequestStepUpOtpRequiresAuth confirms an unauthenticated caller is denied.
func TestRequestStepUpOtpRequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewAdminHandler(s, testAdminAuth()).
		WithOTP(&fakeSender{}, zerolog.Nop(), true)
	_, err := h.RequestStepUpOtp(noopCtx(), &identityv1.RequestStepUpOtpRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

// TestGrantRootRejectsWithoutOtp asserts that a grant with an absent or
// wrong step-up code is refused and changes nothing.
func TestGrantRootRejectsWithoutOtp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	actor := newRootUser(t, s, "kc-tr-actor-1", "tractor1@example.example.org")
	target, err := s.JITProvision(ctx, "kc-tr-target-1", "trtarget1@example.example.org", "Target")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth()).
		WithOTP(&fakeSender{}, zerolog.Nop(), true)

	// (a) No OTP at all.
	if _, err := h.GrantRoot(adminCtx(actor.ID.String()),
		&identityv1.GrantRootRequest{UserId: target.ID.String()}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty otp: want InvalidArgument, got %v", err)
	}
	// (b) Wrong OTP (no code was ever minted for the actor).
	if _, err := h.GrantRoot(adminCtx(actor.ID.String()),
		&identityv1.GrantRootRequest{UserId: target.ID.String(), Otp: "000000"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad otp: want InvalidArgument, got %v", err)
	}
	got, err := s.GetUser(ctx, target.ID)
	if err != nil {
		t.Fatalf("get target: %v", err)
	}
	if got.IsRoot {
		t.Fatal("target became root despite invalid confirmation code")
	}
}

// TestGrantRootSucceedsWithValidOtp asserts that a valid, freshly-minted
// step_up code lets the grant proceed, that both stay root, and that the code
// is single-use.
func TestGrantRootSucceedsWithValidOtp(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	actor := newRootUser(t, s, "kc-tr-actor-2", "tractor2@example.example.org")
	target, err := s.JITProvision(ctx, "kc-tr-target-2", "trtarget2@example.example.org", "Target")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth()).
		WithOTP(&fakeSender{}, zerolog.Nop(), true)

	code := stepUpCodeFor(t, s, actor.ID.String())
	resp, err := h.GrantRoot(adminCtx(actor.ID.String()),
		&identityv1.GrantRootRequest{UserId: target.ID.String(), Otp: code})
	if err != nil {
		t.Fatalf("GrantRoot with valid otp: %v", err)
	}
	if !resp.GetUser().GetIsRoot() {
		t.Fatal("target is not root after a valid grant")
	}
	still, err := s.GetUser(ctx, actor.ID)
	if err != nil {
		t.Fatalf("get actor: %v", err)
	}
	if !still.IsRoot {
		t.Fatal("granting root must not take it from the granter")
	}

	// Single-use: reusing the same code must now fail.
	if _, err := h.RevokeRoot(adminCtx(actor.ID.String()),
		&identityv1.RevokeRootRequest{UserId: target.ID.String(), Otp: code}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("reused otp: want InvalidArgument, got %v", err)
	}
}
