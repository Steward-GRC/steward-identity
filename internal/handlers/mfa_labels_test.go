// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// enrollConfirmedTotp drives the real begin/confirm flow so the user ends with
// a confirmed TOTP factor.
func enrollConfirmedTotp(t *testing.T, h *handlers.ReadHandler, userID string) {
	t.Helper()
	ctx := context.Background()
	begin, err := h.EnrollTotpBegin(ctx, &identityv1.EnrollTotpBeginRequest{UserId: userID})
	if err != nil {
		t.Fatalf("EnrollTotpBegin: %v", err)
	}
	secret := secretFromURI(t, begin.OtpauthUri)
	if _, err := h.EnrollTotpConfirm(ctx, &identityv1.EnrollTotpConfirmRequest{UserId: userID, Code: codeFor(t, secret)}); err != nil {
		t.Fatalf("EnrollTotpConfirm: %v", err)
	}
}

// totpFactorLabel returns the label on the caller's listed TOTP factor.
func totpFactorLabel(t *testing.T, h *handlers.ReadHandler, userID string) (string, bool) {
	t.Helper()
	lf, err := h.ListUserFactors(context.Background(), &identityv1.ListUserFactorsRequest{UserId: userID})
	if err != nil {
		t.Fatalf("ListUserFactors: %v", err)
	}
	for _, f := range lf.Factors {
		if f.Kind == "totp" {
			return f.Label, true
		}
	}
	return "", false
}

// --- RenameMFAMethod: TOTP factor ---

func TestRenameMFAMethod_Totp(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-rn-totp", "rntotp@example.com")
	enrollConfirmedTotp(t, h, u.ID.String())

	// Default: no label yet.
	if lbl, ok := totpFactorLabel(t, h, u.ID.String()); !ok || lbl != "" {
		t.Fatalf("fresh totp factor: want empty label, got %q (present=%v)", lbl, ok)
	}

	// Rename → surfaced in the list path.
	if _, err := h.RenameMFAMethod(ctx, &identityv1.RenameMFAMethodRequest{
		UserId: u.ID.String(), MethodId: "totp", Label: "an identity provider Authenticator",
	}); err != nil {
		t.Fatalf("RenameMFAMethod: %v", err)
	}
	if lbl, ok := totpFactorLabel(t, h, u.ID.String()); !ok || lbl != "an identity provider Authenticator" {
		t.Fatalf("after rename: want 'an identity provider Authenticator', got %q (present=%v)", lbl, ok)
	}
}

func TestRenameMFAMethod_TotpNotEnrolled(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	u := seedUser(t, s, "kc-rn-totp-none", "rntotpnone@example.com")
	_, err := h.RenameMFAMethod(context.Background(), &identityv1.RenameMFAMethodRequest{
		UserId: u.ID.String(), MethodId: "totp", Label: "x",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("rename totp with no enrollment: want NotFound, got %v", err)
	}
}

func TestRenameMFAMethod_EmailRejected(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	u := seedUser(t, s, "kc-rn-email", "rnemail@example.com")
	_, err := h.RenameMFAMethod(context.Background(), &identityv1.RenameMFAMethodRequest{
		UserId: u.ID.String(), MethodId: "email", Label: "My inbox",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rename email factor: want FailedPrecondition, got %v", err)
	}
}

func TestRenameMFAMethod_Validation(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	u := seedUser(t, s, "kc-rn-val", "rnval@example.com")

	// Missing method id.
	if _, err := h.RenameMFAMethod(context.Background(), &identityv1.RenameMFAMethodRequest{
		UserId: u.ID.String(), MethodId: "", Label: "x",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty method_id: want InvalidArgument, got %v", err)
	}

	// Over-long label.
	if _, err := h.RenameMFAMethod(context.Background(), &identityv1.RenameMFAMethodRequest{
		UserId: u.ID.String(), MethodId: "totp", Label: strings.Repeat("z", 129),
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("over-long label: want InvalidArgument, got %v", err)
	}
}

// --- RenameMFAMethod: passkey ---

func TestRenameMFAMethod_Passkey(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-rn-pk", "rnpk@example.com")
	if err := s.InsertWebauthnCredential(ctx, store.WebauthnCredential{
		CredentialID: "pk-cred-1",
		UserID:       u.ID,
		PublicKey:    []byte{0xa5, 0x01, 0x02},
		AAGUID:       make([]byte, 16),
		Transports:   []string{"internal"},
		Label:        "Passkey",
	}); err != nil {
		t.Fatalf("InsertWebauthnCredential: %v", err)
	}

	if _, err := h.RenameMFAMethod(ctx, &identityv1.RenameMFAMethodRequest{
		UserId: u.ID.String(), MethodId: "pk-cred-1", Label: "1Password",
	}); err != nil {
		t.Fatalf("RenameMFAMethod (passkey): %v", err)
	}
	list, err := s.ListWebauthnCredentials(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListWebauthnCredentials: err=%v len=%d", err, len(list))
	}
	if list[0].Label != "1Password" {
		t.Fatalf("want passkey label '1Password', got %q", list[0].Label)
	}
}

func TestRenameMFAMethod_UnknownPasskey(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	u := seedUser(t, s, "kc-rn-pk-unknown", "rnpkunknown@example.com")
	_, err := h.RenameMFAMethod(context.Background(), &identityv1.RenameMFAMethodRequest{
		UserId: u.ID.String(), MethodId: "no-such-credential", Label: "x",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("rename unknown passkey: want NotFound, got %v", err)
	}
}

// A user cannot label another user's passkey: addressed only by the caller's
// own user_id, so the other user's credential is invisible (NotFound) and its
// label is untouched.
func TestRenameMFAMethod_PasskeyCrossUserDenied(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	owner := seedUser(t, s, "kc-rn-pk-owner", "rnpkowner@example.com")
	attacker := seedUser(t, s, "kc-rn-pk-attacker", "rnpkattacker@example.com")
	if err := s.InsertWebauthnCredential(ctx, store.WebauthnCredential{
		CredentialID: "owner-cred",
		UserID:       owner.ID,
		PublicKey:    []byte{0xa5, 0x01, 0x02},
		AAGUID:       make([]byte, 16),
		Transports:   []string{"internal"},
		Label:        "Owner key",
	}); err != nil {
		t.Fatalf("InsertWebauthnCredential: %v", err)
	}

	// Attacker (their user_id) tries to rename the owner's credential.
	_, err := h.RenameMFAMethod(ctx, &identityv1.RenameMFAMethodRequest{
		UserId: attacker.ID.String(), MethodId: "owner-cred", Label: "pwned",
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("cross-user passkey rename: want NotFound, got %v", err)
	}
	// Owner's label is unchanged.
	list, _ := s.ListWebauthnCredentials(ctx, owner.ID)
	if len(list) != 1 || list[0].Label != "Owner key" {
		t.Fatalf("owner label leaked: %+v", list)
	}
}
