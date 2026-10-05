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

func TestReplaceUserIdpGroups(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-adg", "adg@e", "ADG")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	// Set initial ad groups.
	if err := s.ReplaceUserIdpGroups(ctx, u.ID, []string{"alpha", "beta", "gamma"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups: %v", err)
	}

	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(got.IdpGroups) != 3 {
		t.Fatalf("expected 3 ad groups, got %v", got.IdpGroups)
	}
	// Results should be sorted (ORDER BY idp_group_name).
	if got.IdpGroups[0] != "alpha" || got.IdpGroups[1] != "beta" || got.IdpGroups[2] != "gamma" {
		t.Fatalf("expected sorted ad groups, got %v", got.IdpGroups)
	}

	// Replace (overwrite) with a different set — idempotent overwrite.
	if err := s.ReplaceUserIdpGroups(ctx, u.ID, []string{"delta"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups (overwrite): %v", err)
	}
	got, err = s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser after overwrite: %v", err)
	}
	if len(got.IdpGroups) != 1 || got.IdpGroups[0] != "delta" {
		t.Fatalf("expected [delta], got %v", got.IdpGroups)
	}

	// Replace with empty slice — clears all.
	if err := s.ReplaceUserIdpGroups(ctx, u.ID, nil); err != nil {
		t.Fatalf("ReplaceUserIdpGroups (clear): %v", err)
	}
	got, err = s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser after clear: %v", err)
	}
	if len(got.IdpGroups) != 0 {
		t.Fatalf("expected empty ad groups, got %v", got.IdpGroups)
	}
	// Must be non-nil.
	if got.IdpGroups == nil {
		t.Fatal("IdpGroups must be non-nil empty slice")
	}
}

func TestReplaceUserIdpGroupsIdempotent(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-adg2", "adg2@e", "ADG2")
	// Calling twice with the same set is a no-op (ON CONFLICT DO NOTHING).
	if err := s.ReplaceUserIdpGroups(ctx, u.ID, []string{"x", "y"}); err != nil {
		t.Fatalf("first replace: %v", err)
	}
	if err := s.ReplaceUserIdpGroups(ctx, u.ID, []string{"x", "y"}); err != nil {
		t.Fatalf("second replace (idempotent): %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if len(got.IdpGroups) != 2 {
		t.Fatalf("expected 2 groups, got %v", got.IdpGroups)
	}
}

func TestSetPolicyOverride(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-pol", "pol@e", "POL")

	// Set a deny override.
	got, err := s.SetPolicyOverride(ctx, u.ID, "POL-001", "deny", nil, "tester")
	if err != nil {
		t.Fatalf("SetPolicyOverride deny: %v", err)
	}
	if len(got.PolicyOverrides) != 1 {
		t.Fatalf("expected 1 override, got %v", got.PolicyOverrides)
	}
	if got.PolicyOverrides[0].PolicyNumber != "POL-001" || got.PolicyOverrides[0].Effect != "deny" {
		t.Fatalf("unexpected override: %v", got.PolicyOverrides[0])
	}

	// Update to allow.
	got, err = s.SetPolicyOverride(ctx, u.ID, "POL-001", "allow", nil, "tester")
	if err != nil {
		t.Fatalf("SetPolicyOverride allow: %v", err)
	}
	if got.PolicyOverrides[0].Effect != "allow" {
		t.Fatalf("expected effect=allow, got %v", got.PolicyOverrides[0].Effect)
	}

	// Add a second override.
	_, err = s.SetPolicyOverride(ctx, u.ID, "POL-002", "deny", nil, "tester")
	if err != nil {
		t.Fatalf("SetPolicyOverride second: %v", err)
	}
	got, err = s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(got.PolicyOverrides) != 2 {
		t.Fatalf("expected 2 overrides, got %v", got.PolicyOverrides)
	}

	// Clear POL-001 (effect="").
	got, err = s.SetPolicyOverride(ctx, u.ID, "POL-001", "", nil, "tester")
	if err != nil {
		t.Fatalf("SetPolicyOverride clear: %v", err)
	}
	if len(got.PolicyOverrides) != 1 || got.PolicyOverrides[0].PolicyNumber != "POL-002" {
		t.Fatalf("expected only POL-002 remaining, got %v", got.PolicyOverrides)
	}

	// Clearing again is idempotent.
	got, err = s.SetPolicyOverride(ctx, u.ID, "POL-001", "", nil, "tester")
	if err != nil {
		t.Fatalf("SetPolicyOverride clear again: %v", err)
	}
	if len(got.PolicyOverrides) != 1 {
		t.Fatalf("expected 1 override after second clear, got %v", got.PolicyOverrides)
	}

	// Clear all.
	got, err = s.SetPolicyOverride(ctx, u.ID, "POL-002", "", nil, "tester")
	if err != nil {
		t.Fatalf("SetPolicyOverride clear all: %v", err)
	}
	if len(got.PolicyOverrides) != 0 {
		t.Fatalf("expected empty overrides, got %v", got.PolicyOverrides)
	}
	if got.PolicyOverrides == nil {
		t.Fatal("PolicyOverrides must be non-nil empty slice")
	}
}

func TestSetPolicyOverrideInvalidEffect(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, _ := s.JITProvision(ctx, "sub-pol-inv", "polx@e", "POLX")
	_, err := s.SetPolicyOverride(ctx, u.ID, "POL-999", "maybe", nil, "tester")
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestSetPolicyOverrideUserNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	_, err := s.SetPolicyOverride(ctx, uuid.New(), "POL-X", "allow", nil, "tester")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestCountAndListUsersByIdpGroups(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// Provision two users and assign them to distinct AD groups.
	u1, err := s.JITProvision(ctx, "sub-adq1", "adq1@e", "ADQ1")
	if err != nil {
		t.Fatalf("JIT u1: %v", err)
	}
	u2, err := s.JITProvision(ctx, "sub-adq2", "adq2@e", "ADQ2")
	if err != nil {
		t.Fatalf("JIT u2: %v", err)
	}

	if err := s.ReplaceUserIdpGroups(ctx, u1.ID, []string{"AD-A"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u1: %v", err)
	}
	if err := s.ReplaceUserIdpGroups(ctx, u2.ID, []string{"AD-B"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u2: %v", err)
	}

	// Empty input → 0 / empty (fast-path).
	count, err := s.CountUsersByIdpGroups(ctx, nil)
	if err != nil {
		t.Fatalf("CountUsersByIdpGroups(nil): %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0, got %d", count)
	}

	users, err := s.ListUsersByIdpGroups(ctx, nil)
	if err != nil {
		t.Fatalf("ListUsersByIdpGroups(nil): %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("expected empty slice, got %d users", len(users))
	}

	// Single group → 1 user.
	count, err = s.CountUsersByIdpGroups(ctx, []string{"AD-A"})
	if err != nil {
		t.Fatalf("CountUsersByIdpGroups([AD-A]): %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1, got %d", count)
	}

	// Both groups → 2 users.
	count, err = s.CountUsersByIdpGroups(ctx, []string{"AD-A", "AD-B"})
	if err != nil {
		t.Fatalf("CountUsersByIdpGroups([AD-A, AD-B]): %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2, got %d", count)
	}

	users, err = s.ListUsersByIdpGroups(ctx, []string{"AD-A", "AD-B"})
	if err != nil {
		t.Fatalf("ListUsersByIdpGroups([AD-A, AD-B]): %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	// Verify hydration: returned users must have IdpGroups populated.
	for _, u := range users {
		if len(u.IdpGroups) == 0 {
			t.Fatalf("user %s has no IdpGroups (hydration failed)", u.ID)
		}
	}

	// Unknown group → 0.
	count, err = s.CountUsersByIdpGroups(ctx, []string{"AD-UNKNOWN"})
	if err != nil {
		t.Fatalf("CountUsersByIdpGroups([AD-UNKNOWN]): %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 for unknown group, got %d", count)
	}
}

// TestListAndCountAllUsers verifies ListAllUsers / CountAllUsers return every
// ENABLED user (the "Everyone" audience) regardless of AD-group membership, and
// exclude disabled users.
func TestListAndCountAllUsers(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u1, err := s.JITProvision(ctx, "sub-all1", "all1@e", "ALL1")
	if err != nil {
		t.Fatalf("JIT u1: %v", err)
	}
	u2, err := s.JITProvision(ctx, "sub-all2", "all2@e", "ALL2")
	if err != nil {
		t.Fatalf("JIT u2: %v", err)
	}
	// u2 has NO AD groups; it must still be counted by the Everyone audience.
	if err := s.ReplaceUserIdpGroups(ctx, u1.ID, []string{"AD-A"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups u1: %v", err)
	}

	count, err := s.CountAllUsers(ctx)
	if err != nil {
		t.Fatalf("CountAllUsers: %v", err)
	}
	if count != 2 {
		t.Fatalf("CountAllUsers: expected 2 enabled users, got %d", count)
	}

	users, err := s.ListAllUsers(ctx)
	if err != nil {
		t.Fatalf("ListAllUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("ListAllUsers: expected 2 users, got %d", len(users))
	}

	// Disable u2; it must drop out of both the count and the list.
	if _, err := s.SetEnabled(ctx, u2.ID, false, nil, ""); err != nil {
		t.Fatalf("SetEnabled(u2, false): %v", err)
	}
	count, err = s.CountAllUsers(ctx)
	if err != nil {
		t.Fatalf("CountAllUsers after disable: %v", err)
	}
	if count != 1 {
		t.Fatalf("CountAllUsers after disable: expected 1, got %d", count)
	}
	users, err = s.ListAllUsers(ctx)
	if err != nil {
		t.Fatalf("ListAllUsers after disable: %v", err)
	}
	if len(users) != 1 || users[0].ID != u1.ID {
		t.Fatalf("ListAllUsers after disable: expected only u1, got %v", users)
	}
}
