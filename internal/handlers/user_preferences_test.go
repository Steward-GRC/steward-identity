// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

func TestUpdateUserPreferences_RequiresSiteAdmin(t *testing.T) {
	s := newTestStore(t)
	u, err := s.JITProvision(context.Background(), "sub-pref-auth", "pref-auth@example.org", "Pref Auth")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())
	req := &identityv1.UpdateUserPreferencesRequest{UserId: u.ID.String(), Locale: new("fr-FR")}

	if _, err := h.UpdateUserPreferences(noopCtx(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no caller: want PermissionDenied, got %v", err)
	}
	if _, err := h.UpdateUserPreferences(claimsCtx(u.ID.String(), nil), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a person editing their own row through the admin path: want PermissionDenied, got %v", err)
	}
	got, _ := s.GetUser(context.Background(), u.ID)
	if got.Locale != "" {
		t.Fatalf("a refused call changed the locale to %q", got.Locale)
	}
}

func TestUpdateUserPreferences_SetsLocaleAndKeepsTheRest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "sub-pref-admin", "pref-admin@example.org", "Pref Admin")
	target, err := s.JITProvisionWithNames(ctx, "sub-pref-target", "pref-target@example.org", "Tess Target", "Tess", "Target")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	if _, err := s.UpdateUserProfile(ctx, target.ID, target.Email, target.Name, target.FirstName, target.LastName, "Europe/Paris", "en-US"); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	resp, err := h.UpdateUserPreferences(adminCtx(admin.ID.String()), &identityv1.UpdateUserPreferencesRequest{
		UserId: target.ID.String(), Locale: new(" fr-FR "),
	})
	if err != nil {
		t.Fatalf("UpdateUserPreferences: %v", err)
	}
	if resp.GetUser().GetLocale() != "fr-FR" {
		t.Fatalf("answer locale: got %q want fr-FR (trimmed)", resp.GetUser().GetLocale())
	}
	got, _ := s.GetUser(ctx, target.ID)
	if got.Locale != "fr-FR" || got.Timezone != "Europe/Paris" || got.Name != "Tess Target" || got.Email != "pref-target@example.org" {
		t.Fatalf("stored row: locale=%q tz=%q name=%q email=%q", got.Locale, got.Timezone, got.Name, got.Email)
	}

	// An omitted locale changes nothing.
	if _, err := h.UpdateUserPreferences(adminCtx(admin.ID.String()), &identityv1.UpdateUserPreferencesRequest{UserId: target.ID.String()}); err != nil {
		t.Fatalf("no-op: %v", err)
	}
	got, _ = s.GetUser(ctx, target.ID)
	if got.Locale != "fr-FR" {
		t.Fatalf("an empty request changed the locale to %q", got.Locale)
	}
}

func TestUpdateUserPreferences_AuditsUnderTheAdmin(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "sub-pref-aud-admin", "pref-aud-admin@example.org", "Admin")
	target, _ := s.JITProvision(ctx, "sub-pref-aud-target", "pref-aud-target@example.org", "Target")
	h := handlers.NewAdminHandler(s, testAdminAuth())

	if _, err := h.UpdateUserPreferences(adminCtx(admin.ID.String()), &identityv1.UpdateUserPreferencesRequest{
		UserId: target.ID.String(), Locale: new("de-DE"),
	}); err != nil {
		t.Fatalf("UpdateUserPreferences: %v", err)
	}
	events, err := s.PendingAuditEvents(ctx, 100)
	if err != nil {
		t.Fatalf("PendingAuditEvents: %v", err)
	}
	for _, e := range events {
		if e.EventType == "user.preferences.updated" {
			if e.ActorUserID == nil || *e.ActorUserID != admin.ID || e.TargetUserID == nil || *e.TargetUserID != target.ID {
				t.Fatalf("audit actor/target: %+v", e)
			}
			if e.Payload["locale"] != "de-DE" {
				t.Fatalf("audit payload: %+v", e.Payload)
			}
			return
		}
	}
	t.Fatal("no user.preferences.updated audit event")
}

func TestUpdateUserPreferences_RefusesBadInput(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "sub-pref-bad-admin", "pref-bad-admin@example.org", "Admin")
	h := handlers.NewAdminHandler(s, testAdminAuth())

	if _, err := h.UpdateUserPreferences(adminCtx(admin.ID.String()), &identityv1.UpdateUserPreferencesRequest{UserId: "nope", Locale: new("fr-FR")}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad id: want InvalidArgument, got %v", err)
	}
	if _, err := h.UpdateUserPreferences(adminCtx(admin.ID.String()), &identityv1.UpdateUserPreferencesRequest{UserId: uuid.NewString(), Locale: new("fr-FR")}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown user: want NotFound, got %v", err)
	}
	target, _ := s.JITProvision(ctx, "sub-pref-bad-target", "pref-bad-target@example.org", "Target")
	for _, bad := range []string{"not a tag", "x", "12345"} {
		if _, err := h.UpdateUserPreferences(adminCtx(admin.ID.String()), &identityv1.UpdateUserPreferencesRequest{UserId: target.ID.String(), Locale: new(bad)}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("locale %q: want InvalidArgument, got %v", bad, err)
		}
	}
}
