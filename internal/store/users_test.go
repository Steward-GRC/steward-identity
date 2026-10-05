// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

func TestJITProvisionFirstSight(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-1", "alice@example.org", "Alice")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}
	if u.ID == uuid.Nil {
		t.Fatal("expected non-nil id")
	}
	if u.Email != "alice@example.org" {
		t.Fatalf("email: got %q", u.Email)
	}
	// reader is implicit; no stored roles for a JIT user.
	if len(u.Roles) != 0 {
		t.Fatalf("expected no stored roles for JIT user, got %v", u.Roles)
	}
	if !u.Enabled {
		t.Fatal("expected enabled=true")
	}

	// Audit emitted user.created + user.login.success.
	n, err := s.CountAuditPending(ctx)
	if err != nil {
		t.Fatalf("CountAuditPending: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 audit rows, got %d", n)
	}
}

func TestJITProvisionIdempotent(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u1, err := s.JITProvision(ctx, "sub-2", "bob@example.org", "Bob")
	if err != nil {
		t.Fatalf("first JIT: %v", err)
	}
	u2, err := s.JITProvision(ctx, "sub-2", "bob+new@example.org", "Bob Renamed")
	if err != nil {
		t.Fatalf("second JIT: %v", err)
	}
	if u1.ID != u2.ID {
		t.Fatalf("same sub should resolve to same user; got %s vs %s", u1.ID, u2.ID)
	}
	if u2.Email != "bob+new@example.org" {
		t.Fatalf("expected email update on re-JIT; got %q", u2.Email)
	}
}

// TestListUsersByEmailMatchesNameAndUsername pins that the
// user-picker typeahead must resolve on a person's first/last name and login
// username, not only on their email address. The email of the "Ivan" fixture
// deliberately contains none of the name fragments searched for, so a hit can
// only come from the widened predicate.
func TestListUsersByEmailMatchesNameAndUsername(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// Federated user whose given name is "Ivan" and family name "Ivers".
	// The email local-part ("user01") shares nothing with either name, so an
	// email-only predicate would never return this row for a name query.
	ivan, err := s.JITProvisionWithNames(ctx, "sub-ivan", "user01@example.org", "", "Ivan", "Ivers")
	if err != nil {
		t.Fatalf("JITProvisionWithNames ivan: %v", err)
	}

	// Local account with a distinctive username that appears in neither the
	// email nor the display name, isolating the username branch of the match.
	frank, err := s.PreCreateLocalUser(ctx, "zfrank", "z@example.net", "Frank")
	if err != nil {
		t.Fatalf("PreCreateLocalUser frank: %v", err)
	}

	contains := func(users []store.User, id uuid.UUID) bool {
		for _, u := range users {
			if u.ID == id {
				return true
			}
		}
		return false
	}

	// First-name prefix "Iv" must resolve the "Ivan" user.
	byFirst, err := s.ListUsersByEmail(ctx, "Iv", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("search Iv: %v", err)
	}
	if !contains(byFirst, ivan.ID) {
		t.Fatalf(`search "Iv" did not match first_name "Ivan" (got %d users)`, len(byFirst))
	}

	// Last-name fragment must resolve the same user.
	byLast, err := s.ListUsersByEmail(ctx, "iver", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("search iver: %v", err)
	}
	if !contains(byLast, ivan.ID) {
		t.Fatalf(`search "iver" did not match last_name "Ivers"`)
	}

	// Composed "first last" display-name query must resolve too.
	byFull, err := s.ListUsersByEmail(ctx, "ivan ive", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("search full name: %v", err)
	}
	if !contains(byFull, ivan.ID) {
		t.Fatalf(`search "ivan ive" did not match composed display name`)
	}

	// Username fragment must resolve the local account (email/name share nothing).
	byUser, err := s.ListUsersByEmail(ctx, "zfran", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("search zfran: %v", err)
	}
	if !contains(byUser, frank.ID) {
		t.Fatalf(`search "zfran" did not match username "zfrank"`)
	}

	// Email still matches (no regression on the original predicate).
	byEmail, err := s.ListUsersByEmail(ctx, "example.net", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("search email: %v", err)
	}
	if !contains(byEmail, frank.ID) {
		t.Fatalf(`search "example.net" did not match email`)
	}

	// Empty query still returns every user (the "list all" path).
	all, err := s.ListUsersByEmail(ctx, "", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("search empty: %v", err)
	}
	if !contains(all, ivan.ID) || !contains(all, frank.ID) {
		t.Fatalf("empty query did not return all users (got %d)", len(all))
	}

	// A fragment matching nobody returns an empty page, not everyone.
	none, err := s.ListUsersByEmail(ctx, "zzz-no-such-user", 200, "", uuid.Nil)
	if err != nil {
		t.Fatalf("search none: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("expected no matches, got %d", len(none))
	}
}

func TestGetUserNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	_, err := s.GetUser(context.Background(), uuid.New())
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSetEnabled(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-3", "c@e", "C")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	u2, err := s.SetEnabled(ctx, u.ID, false, nil, "tester")
	if err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	if u2.Enabled {
		t.Fatal("expected disabled")
	}
}

// TestUpdateUserProfilePersists is the store-level D6 regression: an admin
// display-name edit must survive a subsequent read. UpdateUserProfile returns
// the fresh row, but a page refresh re-reads via a separate GetUser, so this
// asserts the committed users.name (and email) row — not just the return value.
func TestUpdateUserProfilePersists(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-upd", "dave@example.org", "Dave")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	updated, err := s.UpdateUserProfile(ctx, u.ID, "dave@example.org", "Dave Renamed", "Dave", "Renamed", "America/New_York", "en-US")
	if err != nil {
		t.Fatalf("UpdateUserProfile: %v", err)
	}
	if updated.Name != "Dave Renamed" {
		t.Fatalf("returned name: got %q", updated.Name)
	}
	if updated.FirstName != "Dave" || updated.LastName != "Renamed" {
		t.Fatalf("returned first/last: got %q/%q", updated.FirstName, updated.LastName)
	}
	if updated.Timezone != "America/New_York" || updated.Locale != "en-US" {
		t.Fatalf("returned tz/locale: got %q/%q", updated.Timezone, updated.Locale)
	}

	// Independent re-fetch = what the admin page reads on refresh.
	reloaded, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if reloaded.Name != "Dave Renamed" {
		t.Fatalf("name did not persist to the DB (refresh would revert): got %q", reloaded.Name)
	}
	if reloaded.Email != "dave@example.org" {
		t.Fatalf("email: got %q", reloaded.Email)
	}
	if reloaded.FirstName != "Dave" || reloaded.LastName != "Renamed" {
		t.Fatalf("first/last did not persist: got %q/%q", reloaded.FirstName, reloaded.LastName)
	}
	if reloaded.Timezone != "America/New_York" || reloaded.Locale != "en-US" {
		t.Fatalf("tz/locale did not persist (refresh would revert): got %q/%q", reloaded.Timezone, reloaded.Locale)
	}
}

// TestUpdateUserProfileDefaultsTZLocaleEmpty is the migration-0006 guard: a
// freshly provisioned user has empty timezone/locale (UTC-safe default) until
// they are set, so steward-obligations falls back to UTC rather than erroring.
func TestUpdateUserProfileDefaultsTZLocaleEmpty(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-tzdefault", "tzdefault@example.org", "TZ Default")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Timezone != "" || got.Locale != "" {
		t.Fatalf("new user should default to empty tz/locale, got %q/%q", got.Timezone, got.Locale)
	}
}
