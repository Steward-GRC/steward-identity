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

func newReadHandlerForSetup(t *testing.T, fk *fakeKratos) (*handlers.ReadHandler, bool) {
	t.Helper()
	return handlers.NewReadHandler(newTestStore(t)).WithSignIn(fk), true
}

func TestGetSetupState_NeedsSetup(t *testing.T) {
	h, ok := newReadHandlerForSetup(t, newFakeKratos())
	if !ok {
		return
	}
	resp, err := h.GetSetupState(context.Background(), &identityv1.GetSetupStateRequest{})
	if err != nil {
		t.Fatalf("GetSetupState: %v", err)
	}
	if !resp.NeedsSetup {
		t.Fatal("expected NeedsSetup=true on empty DB")
	}
}

func TestGetSetupState_AfterBootstrap(t *testing.T) {
	fk := newFakeKratos()
	h, ok := newReadHandlerForSetup(t, fk)
	if !ok {
		return
	}

	// Bootstrap a root user first.
	_, err := h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "rootuser",
		Email:    "alice@example.org",
		Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("BootstrapRoot: %v", err)
	}

	resp, err := h.GetSetupState(context.Background(), &identityv1.GetSetupStateRequest{})
	if err != nil {
		t.Fatalf("GetSetupState after bootstrap: %v", err)
	}
	if resp.NeedsSetup {
		t.Fatal("expected NeedsSetup=false after root user created")
	}
}

func TestBootstrapRoot_CreatesUser(t *testing.T) {
	fk := newFakeKratos()
	h, ok := newReadHandlerForSetup(t, fk)
	if !ok {
		return
	}

	resp, err := h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "rootuser",
		Email:    "alice@example.org",
		Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("BootstrapRoot: %v", err)
	}
	if resp.User == nil {
		t.Fatal("expected non-nil user")
	}
	if resp.User.Email != "alice@example.org" {
		t.Fatalf("email: got %q", resp.User.Email)
	}
	if !resp.User.IsRoot {
		t.Fatal("expected is_root=true on returned user")
	}

	u := fk.byUsername("rootuser")
	if u == nil {
		t.Fatal("the Kratos identity was not created")
	}
	if u.password != "Passw0rd!" {
		t.Fatalf("Kratos password: got %q", u.password)
	}
}

func TestBootstrapRoot_SecondCallIsNoOp(t *testing.T) {
	fk := newFakeKratos()
	h, ok := newReadHandlerForSetup(t, fk)
	if !ok {
		return
	}

	_, err := h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "rootuser",
		Email:    "alice@example.org",
		Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("first BootstrapRoot: %v", err)
	}

	// Idempotent: a re-run against an already-bootstrapped system (e.g. the
	// dev seed job, re-run by ArgoCD) must succeed as a no-op rather than
	// erroring, and must NOT create a second root user.
	resp, err := h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "rootuser2",
		Email:    "bob@example.org",
		Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("expected no-op success on second call, got error: %v", err)
	}
	if resp.GetUser() != nil {
		t.Fatalf("expected empty response on no-op, got user %+v", resp.GetUser())
	}

	if fk.byUsername("rootuser2") != nil {
		t.Fatal("expected no second Kratos identity on a no-op re-run")
	}
}

func TestBootstrapRoot_EmptyFields_InvalidArgument(t *testing.T) {
	fk := newFakeKratos()
	h, ok := newReadHandlerForSetup(t, fk)
	if !ok {
		return
	}

	cases := []struct {
		name string
		req  *identityv1.BootstrapRootRequest
	}{
		{"no username", &identityv1.BootstrapRootRequest{Email: "alice@example.org", Password: "p"}},
		{"no email", &identityv1.BootstrapRootRequest{Username: "u", Password: "p"}},
		{"no password", &identityv1.BootstrapRootRequest{Username: "u", Email: "alice@example.org"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.BootstrapRoot(context.Background(), tc.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("expected InvalidArgument, got %v", err)
			}
		})
	}
}

// TestBootstrapRoot_UsernameIsEmail_InvalidArgument covers the setup-form
// autofill trap: a password manager fills the Username field with the
// account's email, so the root user's login id silently becomes an email
// address. BootstrapRoot must reject that up front instead of creating a root
// user whose "username" is unusable for a plain-name login.
func TestBootstrapRoot_UsernameIsEmail_InvalidArgument(t *testing.T) {
	fk := newFakeKratos()
	h, ok := newReadHandlerForSetup(t, fk)
	if !ok {
		return
	}

	_, err := h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "alice@example.org",
		Email:    "alice@example.org",
		Password: "Passw0rd!",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for an email-shaped username, got %v", err)
	}

	// No root user should have been created — GetSetupState must still report
	// NeedsSetup=true.
	state, err := h.GetSetupState(context.Background(), &identityv1.GetSetupStateRequest{})
	if err != nil {
		t.Fatalf("GetSetupState: %v", err)
	}
	if !state.NeedsSetup {
		t.Fatal("expected NeedsSetup=true after a rejected email-username bootstrap attempt")
	}
}

// Without the Kratos admin API the bootstrap declines with the coded
// precondition.
func TestBootstrapRoot_NoKratos_LocalAccountsUnavailable(t *testing.T) {
	h := handlers.NewReadHandler(newTestStore(t))

	_, err := h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "rootuser",
		Email:    "alice@example.org",
		Password: "Passw0rd!",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition without Kratos, got %v", err)
	}
}
