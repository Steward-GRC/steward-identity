// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

func newAdminMFAHandler(t *testing.T) (*handlers.AdminHandler, *store.Store) {
	t.Helper()
	s := newTestStore(t)
	if s == nil {
		return nil, nil
	}
	auth := testAdminAuth()
	return handlers.NewAdminHandler(s, auth), s
}

// seedAdminAndTarget creates an admin actor and a distinct target user so tests
// prove the admin RPCs act on ANY user (the target), not the caller.
func seedAdminAndTarget(t *testing.T, s *store.Store, tag string) (admin, target store.User) {
	t.Helper()
	ctx := context.Background()
	var err error
	admin, err = s.JITProvision(ctx, "kc-admin-"+tag, "admin-"+tag+"@example.com", "Admin")
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	target, err = s.JITProvision(ctx, "kc-target-"+tag, "target-"+tag+"@example.com", "Target")
	if err != nil {
		t.Fatalf("seed target: %v", err)
	}
	return admin, target
}

func seedConfirmedTotp(t *testing.T, s *store.Store, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertPendingTotp(ctx, userID, "sealed"); err != nil {
		t.Fatalf("UpsertPendingTotp: %v", err)
	}
	if err := s.ConfirmTotp(ctx, userID); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
}

func seedPasskey(t *testing.T, s *store.Store, userID uuid.UUID, credID, label string) {
	t.Helper()
	if err := s.InsertWebauthnCredential(context.Background(), store.WebauthnCredential{
		CredentialID: credID,
		UserID:       userID,
		PublicKey:    []byte{0xa5, 0x01, 0x02},
		AAGUID:       make([]byte, 16),
		Transports:   []string{"usb"},
		Label:        label,
	}); err != nil {
		t.Fatalf("InsertWebauthnCredential: %v", err)
	}
}

func TestAdminMFARequiresSiteAdmin(t *testing.T) {
	h, s := newAdminMFAHandler(t)
	_, target := seedAdminAndTarget(t, s, "authz")
	uid := target.ID.String()

	if _, err := h.AdminListUserFactors(noopCtx(), &identityv1.AdminListUserFactorsRequest{UserId: uid}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AdminListUserFactors: want PermissionDenied, got %v", err)
	}
	if _, err := h.AdminRemoveUserFactor(noopCtx(), &identityv1.AdminRemoveUserFactorRequest{UserId: uid, MethodId: "totp"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AdminRemoveUserFactor: want PermissionDenied, got %v", err)
	}
	if _, err := h.AdminRenameUserFactor(noopCtx(), &identityv1.AdminRenameUserFactorRequest{UserId: uid, MethodId: "totp", Label: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AdminRenameUserFactor: want PermissionDenied, got %v", err)
	}
}

func TestAdminListUserFactors(t *testing.T) {
	h, s := newAdminMFAHandler(t)
	admin, target := seedAdminAndTarget(t, s, "list")
	seedConfirmedTotp(t, s, target.ID)
	seedPasskey(t, s, target.ID, "cred-a", "YubiKey")

	resp, err := h.AdminListUserFactors(adminCtx(admin.ID.String()), &identityv1.AdminListUserFactorsRequest{UserId: target.ID.String()})
	if err != nil {
		t.Fatalf("AdminListUserFactors: %v", err)
	}
	byID := map[string]*identityv1.UserFactor{}
	for _, f := range resp.GetFactors() {
		byID[f.GetId()] = f
	}
	totp, ok := byID["totp"]
	if !ok || totp.GetKind() != "totp" || totp.GetEnrolledAt() == "" {
		t.Fatalf("totp factor missing/incomplete: %+v", byID)
	}
	pk, ok := byID["cred-a"]
	if !ok || pk.GetKind() != "passkey" || pk.GetLabel() != "YubiKey" || pk.GetEnrolledAt() == "" {
		t.Fatalf("passkey factor missing/incomplete: %+v", byID)
	}
	em, ok := byID["email"]
	if !ok || em.GetKind() != "email" {
		t.Fatalf("email factor missing: %+v", byID)
	}
}

func TestAdminListUserFactorsMissingUser(t *testing.T) {
	h, s := newAdminMFAHandler(t)
	admin, _ := seedAdminAndTarget(t, s, "miss")
	_, err := h.AdminListUserFactors(adminCtx(admin.ID.String()), &identityv1.AdminListUserFactorsRequest{UserId: uuid.New().String()})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("missing user: want NotFound, got %v", err)
	}
}

func TestAdminRemoveUserFactor(t *testing.T) {
	h, s := newAdminMFAHandler(t)
	admin, target := seedAdminAndTarget(t, s, "remove")
	seedConfirmedTotp(t, s, target.ID)
	seedPasskey(t, s, target.ID, "cred-r", "Key")
	ctx := adminCtx(admin.ID.String())
	uid := target.ID.String()

	// email is not removable
	if _, err := h.AdminRemoveUserFactor(ctx, &identityv1.AdminRemoveUserFactorRequest{UserId: uid, MethodId: "email"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove email: want FailedPrecondition, got %v", err)
	}
	// missing method_id
	if _, err := h.AdminRemoveUserFactor(ctx, &identityv1.AdminRemoveUserFactorRequest{UserId: uid, MethodId: ""}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("remove empty method: want InvalidArgument, got %v", err)
	}
	// unknown passkey id -> NotFound
	if _, err := h.AdminRemoveUserFactor(ctx, &identityv1.AdminRemoveUserFactorRequest{UserId: uid, MethodId: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("remove unknown passkey: want NotFound, got %v", err)
	}
	// totp removal
	if _, err := h.AdminRemoveUserFactor(ctx, &identityv1.AdminRemoveUserFactorRequest{UserId: uid, MethodId: "totp"}); err != nil {
		t.Fatalf("remove totp: %v", err)
	}
	// passkey removal by credential id
	if _, err := h.AdminRemoveUserFactor(ctx, &identityv1.AdminRemoveUserFactorRequest{UserId: uid, MethodId: "cred-r"}); err != nil {
		t.Fatalf("remove passkey: %v", err)
	}
	// both gone
	resp, err := h.AdminListUserFactors(ctx, &identityv1.AdminListUserFactorsRequest{UserId: uid})
	if err != nil {
		t.Fatalf("list after removal: %v", err)
	}
	for _, f := range resp.GetFactors() {
		if f.GetKind() != "email" {
			t.Fatalf("expected only email factor left, got %+v", resp.GetFactors())
		}
	}
}

func TestAdminRenameUserFactor(t *testing.T) {
	h, s := newAdminMFAHandler(t)
	admin, target := seedAdminAndTarget(t, s, "rename")
	seedConfirmedTotp(t, s, target.ID)
	seedPasskey(t, s, target.ID, "cred-n", "old")
	ctx := adminCtx(admin.ID.String())
	uid := target.ID.String()

	// email not labellable
	if _, err := h.AdminRenameUserFactor(ctx, &identityv1.AdminRenameUserFactorRequest{UserId: uid, MethodId: "email", Label: "x"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rename email: want FailedPrecondition, got %v", err)
	}
	// label too long
	if _, err := h.AdminRenameUserFactor(ctx, &identityv1.AdminRenameUserFactorRequest{UserId: uid, MethodId: "totp", Label: strings.Repeat("a", 200)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("rename too long: want InvalidArgument, got %v", err)
	}
	// totp rename
	if _, err := h.AdminRenameUserFactor(ctx, &identityv1.AdminRenameUserFactorRequest{UserId: uid, MethodId: "totp", Label: "Work TOTP"}); err != nil {
		t.Fatalf("rename totp: %v", err)
	}
	// passkey rename
	if _, err := h.AdminRenameUserFactor(ctx, &identityv1.AdminRenameUserFactorRequest{UserId: uid, MethodId: "cred-n", Label: "New name"}); err != nil {
		t.Fatalf("rename passkey: %v", err)
	}
	// verify persisted via list
	resp, err := h.AdminListUserFactors(ctx, &identityv1.AdminListUserFactorsRequest{UserId: uid})
	if err != nil {
		t.Fatalf("list after rename: %v", err)
	}
	for _, f := range resp.GetFactors() {
		if f.GetId() == "totp" && f.GetLabel() != "Work TOTP" {
			t.Fatalf("totp label not persisted: %q", f.GetLabel())
		}
		if f.GetId() == "cred-n" && f.GetLabel() != "New name" {
			t.Fatalf("passkey label not persisted: %q", f.GetLabel())
		}
	}
	// rename missing totp -> NotFound
	_, other := seedAdminAndTarget(t, s, "rename2")
	if _, err := h.AdminRenameUserFactor(ctx, &identityv1.AdminRenameUserFactorRequest{UserId: other.ID.String(), MethodId: "totp", Label: "x"}); status.Code(err) != codes.NotFound {
		t.Fatalf("rename missing totp: want NotFound, got %v", err)
	}
}
