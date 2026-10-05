// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

func TestCreateLocalUser(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-clu-actor", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	resp, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "bob", Email: "bob@example.org", Name: "Bob", Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}
	if resp.User.Email != "bob@example.org" || !resp.User.LocalAccount {
		t.Fatalf("unexpected user: %+v", resp.User)
	}
	i := fk.byUsername("bob")
	if i == nil {
		t.Fatal("Kratos identity was not created")
	}
	if i.password != "Passw0rd!" || i.account.Email != "bob@example.org" || i.account.Name != "Bob" {
		t.Fatalf("Kratos identity: %+v", i)
	}
}

func TestCreateLocalUser_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(newFakeKratos())
	_, err := h.CreateLocalUser(noopCtx(), &identityv1.CreateLocalUserRequest{
		Username: "x", Email: "x@example.org", Name: "X", Password: "p",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

// Without the Kratos admin API the RPC declines with the coded precondition.
func TestCreateLocalUser_NoKratos_LocalAccountsUnavailable(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "sub-nil-kratos", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth())

	_, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "x", Email: "x@example.org", Name: "X", Password: "p",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
	if info, _ := apperrgrpc.FromError(err); info.Symbol != "LOCAL_ACCOUNTS_UNAVAILABLE" {
		t.Fatalf("symbol: got %q", info.Symbol)
	}
}

func TestResetUserPassword(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-rup-actor", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	target, err := s.PreCreateLocalUser(context.Background(), "carol", "carol@example.org", "Carol")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	id := fk.add(kratos.Account{Username: "carol", Email: "carol@example.org", Name: "Carol"}, "old")

	if _, err := h.ResetUserPassword(adminCtx(admin.ID.String()), &identityv1.ResetUserPasswordRequest{
		UserId: target.ID.String(), NewPassword: "NewPass1!",
	}); err != nil {
		t.Fatalf("ResetUserPassword: %v", err)
	}
	if got := fk.identities[id].password; got != "NewPass1!" {
		t.Fatalf("expected password set, got %q", got)
	}
}

func TestUpdateUserProfile_LocalUser(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-upd-actor", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	target, err := s.PreCreateLocalUser(context.Background(), "dave", "dave@example.org", "Dave")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	id := fk.add(kratos.Account{Username: "dave", Email: "dave@example.org", Name: "Dave"}, "pw")

	resp, err := h.UpdateUserProfile(adminCtx(admin.ID.String()), &identityv1.UpdateUserProfileRequest{
		UserId: target.ID.String(), Name: "Dave D", Email: "dave.d@example.org",
	})
	if err != nil {
		t.Fatalf("UpdateUserProfile: %v", err)
	}
	if resp.User.Name != "Dave D" {
		t.Fatalf("name: got %q", resp.User.Name)
	}
	reloaded, err := s.GetUser(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("GetUser after update: %v", err)
	}
	if reloaded.Name != "Dave D" || reloaded.Email != "dave.d@example.org" {
		t.Fatalf("DB row did not persist: %+v", reloaded)
	}
	if i := fk.identities[id]; i.account.Name != "Dave D" || i.account.Email != "dave.d@example.org" {
		t.Fatalf("Kratos traits: %+v", i.account)
	}
}

// An SSO account has no Kratos password identity to update; the row is the
// only thing written.
func TestUpdateUserProfile_Federated(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-upd-fed-actor", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	target, err := s.JITProvision(context.Background(), "sub-fed-target", "ivan@partner.example.net", "Ivan")
	if err != nil {
		t.Fatalf("JITProvision target: %v", err)
	}
	resp, err := h.UpdateUserProfile(adminCtx(admin.ID.String()), &identityv1.UpdateUserProfileRequest{
		UserId: target.ID.String(), Name: "Ivan I", Email: "ivan@partner.example.net",
	})
	if err != nil {
		t.Fatalf("UpdateUserProfile: %v", err)
	}
	if resp.User.Name != "Ivan I" {
		t.Fatalf("response name: got %q", resp.User.Name)
	}
	reloaded, err := s.GetUser(context.Background(), target.ID)
	if err != nil || reloaded.Name != "Ivan I" {
		t.Fatalf("DB name did not persist: %q %v", reloaded.Name, err)
	}
	if len(fk.identities) != 0 {
		t.Fatal("Kratos must not be written for an SSO account")
	}
}

func TestCreateLocalUser_CreateIdentityFails(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	fk.failCreate = errors.New("injected create error")
	admin, _ := s.JITProvision(context.Background(), "sub-spf-actor", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	_, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "erin", Email: "erin@example.org", Name: "Erin", Password: "Passw0rd!",
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected codes.Internal, got %v", err)
	}
	if _, storeErr := s.GetUserByUsername(context.Background(), "erin"); storeErr == nil {
		t.Fatal("expected no platform row after the failed create")
	}
}

// A username that is an email is refused before anything is created.
func TestCreateLocalUser_UsernameIsEmail(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-email-user", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	_, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "frank@example.org", Email: "frank@example.org", Name: "Frank", Password: "Passw0rd!",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
	if len(fk.identities) != 0 {
		t.Fatal("expected no Kratos identity")
	}
}

func TestCreateLocalUser_InvalidEmail(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-inv-email", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	_, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "grace", Email: "grace@exmaple org", Name: "Grace", Password: "Passw0rd!",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for malformed email, got %v", err)
	}
	if len(fk.identities) != 0 {
		t.Fatal("expected no Kratos identity for an invalid email")
	}
}

func TestCreateLocalUser_DuplicateUsername(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-dup-user", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	if _, err := s.PreCreateLocalUser(context.Background(), "heidi", "heidi@example.org", "Heidi"); err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	_, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "HEIDI", Email: "heidi.new@example.org", Name: "Heidi", Password: "Passw0rd!",
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}
	if len(fk.identities) != 0 {
		t.Fatal("expected no Kratos identity when the username pre-check fails")
	}
}

func TestCreateLocalUser_DuplicateEmail(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "sub-dup-email", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(newFakeKratos())

	if _, err := s.PreCreateLocalUser(context.Background(), "firstuser", "shared@example.org", "First"); err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	_, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "seconduser", Email: "SHARED@example.org", Name: "Second", Password: "Passw0rd!",
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}
}

func TestCreateLocalUser_RetryAfterCreateFailure(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-retry-actor", "alice@example.org", "Alice")
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)
	req := &identityv1.CreateLocalUserRequest{Username: "retryuser", Email: "retry@example.org", Name: "Retry", Password: "Passw0rd!"}

	fk.failCreate = errors.New("injected create error")
	if _, err := h.CreateLocalUser(adminCtx(admin.ID.String()), req); status.Code(err) != codes.Internal {
		t.Fatalf("first attempt: expected Internal, got %v", err)
	}
	fk.failCreate = nil
	resp, err := h.CreateLocalUser(adminCtx(admin.ID.String()), req)
	if err != nil {
		t.Fatalf("retry should succeed: %v", err)
	}
	if resp.User.Email != "retry@example.org" {
		t.Fatalf("email: got %q", resp.User.Email)
	}
	if i := fk.byUsername("retryuser"); i == nil || i.password != "Passw0rd!" {
		t.Fatal("expected the Kratos identity with its password after the retry")
	}
}
