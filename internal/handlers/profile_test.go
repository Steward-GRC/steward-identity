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

func TestUpdateMyProfile_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewAdminHandler(s, testAdminAuth())
	_, err := h.UpdateMyProfile(noopCtx(), &identityv1.UpdateMyProfileRequest{FirstName: new("X")})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated without claims, got %v", err)
	}
}

// TestUpdateMyProfile_NonAdminEditsOwn proves the RPC is self-service (NOT
// site-admin gated): a plain authenticated user edits their own first/last name
// and the display name is derived from the parts.
func TestUpdateMyProfile_NonAdminEditsOwn(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "kc-prof-1", "prof1@example.com", "Prof One")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	resp, err := h.UpdateMyProfile(claimsCtx(u.ID.String(), nil), &identityv1.UpdateMyProfileRequest{
		FirstName: new("Renamed"),
		LastName:  new("Person"),
	})
	if err != nil {
		t.Fatalf("UpdateMyProfile: %v", err)
	}
	got := resp.GetUser()
	if got.GetFirstName() != "Renamed" || got.GetLastName() != "Person" {
		t.Fatalf("first/last: got %q/%q", got.GetFirstName(), got.GetLastName())
	}
	// Display name is derived from first+last.
	if got.GetName() != "Renamed Person" {
		t.Fatalf("derived name: got %q want %q", got.GetName(), "Renamed Person")
	}

	// Persisted (re-read the row).
	reread, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if reread.FirstName != "Renamed" || reread.LastName != "Person" || reread.Name != "Renamed Person" {
		t.Fatalf("not persisted: %q/%q/%q", reread.FirstName, reread.LastName, reread.Name)
	}
}

// TestUpdateMyProfile_PartialUpdatePreservesOther verifies presence-tracking: an
// omitted (nil) field leaves the stored value unchanged, and the derived display
// name recomposes from the effective parts.
func TestUpdateMyProfile_PartialUpdatePreservesOther(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvisionWithNames(ctx, "kc-prof-2", "prof2@example.com", "Ann Smith", "Ann", "Smith")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	// Update only last_name; first_name omitted must be preserved.
	resp, err := h.UpdateMyProfile(claimsCtx(u.ID.String(), nil), &identityv1.UpdateMyProfileRequest{
		LastName: new("Jones"),
	})
	if err != nil {
		t.Fatalf("UpdateMyProfile: %v", err)
	}
	got := resp.GetUser()
	if got.GetFirstName() != "Ann" {
		t.Fatalf("first_name should be preserved, got %q", got.GetFirstName())
	}
	if got.GetLastName() != "Jones" {
		t.Fatalf("last_name: got %q want Jones", got.GetLastName())
	}
	if got.GetName() != "Ann Jones" {
		t.Fatalf("derived name: got %q want %q", got.GetName(), "Ann Jones")
	}
}

// TestUpdateMyProfile_SetsTimezoneLocale is the slice-9 self-service path: a user
// sets their own timezone/locale, they round-trip on the proto User, and persist
// so the obligations service's GetUser lookup reads the real zone. Presence-tracking
// also applies: omitting timezone/locale leaves the stored value untouched.
func TestUpdateMyProfile_SetsTimezoneLocale(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "kc-prof-tz", "proftz@example.com", "Prof TZ")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	// New user defaults to empty (UTC-safe).
	if u.Timezone != "" || u.Locale != "" {
		t.Fatalf("new user should default empty tz/locale, got %q/%q", u.Timezone, u.Locale)
	}

	resp, err := h.UpdateMyProfile(claimsCtx(u.ID.String(), nil), &identityv1.UpdateMyProfileRequest{
		Timezone: new("America/New_York"),
		Locale:   new("en-US"),
	})
	if err != nil {
		t.Fatalf("UpdateMyProfile: %v", err)
	}
	if got := resp.GetUser(); got.GetTimezone() != "America/New_York" || got.GetLocale() != "en-US" {
		t.Fatalf("proto tz/locale: got %q/%q", got.GetTimezone(), got.GetLocale())
	}

	// Persisted for a separate GetUser (what the obligations service calls).
	reread, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if reread.Timezone != "America/New_York" || reread.Locale != "en-US" {
		t.Fatalf("tz/locale not persisted: %q/%q", reread.Timezone, reread.Locale)
	}

	// Presence-tracking: updating only locale preserves the timezone.
	resp2, err := h.UpdateMyProfile(claimsCtx(u.ID.String(), nil), &identityv1.UpdateMyProfileRequest{
		Locale: new("fr-FR"),
	})
	if err != nil {
		t.Fatalf("UpdateMyProfile locale-only: %v", err)
	}
	if got := resp2.GetUser(); got.GetTimezone() != "America/New_York" || got.GetLocale() != "fr-FR" {
		t.Fatalf("locale-only update should preserve tz: got %q/%q", got.GetTimezone(), got.GetLocale())
	}
}

// TestUpdateMyProfile_NoFieldsNoop verifies an empty request is a harmless no-op
// that returns the current row unchanged.
func TestUpdateMyProfile_NoFieldsNoop(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, err := s.JITProvisionWithNames(ctx, "kc-prof-3", "prof3@example.com", "Bob Lee", "Bob", "Lee")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	resp, err := h.UpdateMyProfile(claimsCtx(u.ID.String(), nil), &identityv1.UpdateMyProfileRequest{})
	if err != nil {
		t.Fatalf("UpdateMyProfile: %v", err)
	}
	got := resp.GetUser()
	if got.GetFirstName() != "Bob" || got.GetLastName() != "Lee" || got.GetName() != "Bob Lee" {
		t.Fatalf("no-op changed row: %q/%q/%q", got.GetFirstName(), got.GetLastName(), got.GetName())
	}
}
