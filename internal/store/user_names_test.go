// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
)

// TestJITProvisionWithNamesPopulatesFirstLast verifies that JIT-provisioning
// with forwarded given/family name hints stores first/last on the row and, when
// no display name was forwarded, composes `name` from the parts.
func TestJITProvisionWithNamesPopulatesFirstLast(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// No display name forwarded, but first/last present -> name composed.
	u, err := s.JITProvisionWithNames(ctx, "kc-names-1", "grace@example.org", "", "Grace", "Green")
	if err != nil {
		t.Fatalf("JITProvisionWithNames: %v", err)
	}
	if u.FirstName != "Grace" || u.LastName != "Green" {
		t.Fatalf("first/last: got %q/%q", u.FirstName, u.LastName)
	}
	if u.Name != "Grace Green" {
		t.Fatalf("composed name: got %q want %q", u.Name, "Grace Green")
	}

	// Re-fetch to prove first/last persisted (what me()/refresh reads).
	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.FirstName != "Grace" || got.LastName != "Green" {
		t.Fatalf("first/last did not persist: got %q/%q", got.FirstName, got.LastName)
	}
}

// TestJITProvisionWithNamesDerivesDisplayName verifies the display name is
// DERIVED from the structured parts even when a different `name` claim was also
// forwarded — first/last are the source of truth (name = "first last").
func TestJITProvisionWithNamesDerivesDisplayName(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvisionWithNames(ctx, "kc-names-2", "frank@example.org", "Frank B. Foster", "Frank", "Foster")
	if err != nil {
		t.Fatalf("JITProvisionWithNames: %v", err)
	}
	if u.Name != "Frank Foster" {
		t.Fatalf("display name should be derived from first+last: got %q want %q", u.Name, "Frank Foster")
	}
	if u.FirstName != "Frank" || u.LastName != "Foster" {
		t.Fatalf("first/last: got %q/%q", u.FirstName, u.LastName)
	}
}

// TestJITProvisionBackfillsBlankNames verifies the migration default: a user
// created via the legacy 3-arg JITProvision (no structured name) has empty
// first/last (NOT NULL DEFAULT ”) rather than a scan error.
func TestJITProvisionBackfillsBlankNames(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "kc-names-3", "blank@example.org", "Blank User")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}
	if u.FirstName != "" || u.LastName != "" {
		t.Fatalf("expected blank first/last, got %q/%q", u.FirstName, u.LastName)
	}
}

// A user's own name must survive a later SSO login: once a name is set, the
// subject-keyed JIT re-provision fills only when the stored value is empty
// (the "fill only when empty" rule).
func TestJITProvisionDoesNotOverwriteExistingName(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	if _, err := s.JITProvisionWithNames(ctx, "kc-noover", "u@example.org", "Alice A", "Alice", "A"); err != nil {
		t.Fatalf("first JITProvisionWithNames: %v", err)
	}
	// Same subject, IdP now asserts a different name — must NOT overwrite.
	u, err := s.JITProvisionWithNames(ctx, "kc-noover", "u@example.org", "Alicia B", "Alicia", "B")
	if err != nil {
		t.Fatalf("second JITProvisionWithNames: %v", err)
	}
	if u.FirstName != "Alice" || u.LastName != "A" || u.Name != "Alice A" {
		t.Fatalf("re-login overwrote name: got %q / %q / %q, want Alice / A / Alice A", u.FirstName, u.LastName, u.Name)
	}
}

// The complement: when the stored name IS empty, a later IdP login still fills it.
func TestJITProvisionFillsEmptyNameOnRelogin(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	if _, err := s.JITProvision(ctx, "kc-fill", "f@example.org", ""); err != nil {
		t.Fatalf("first JITProvision: %v", err)
	}
	u, err := s.JITProvisionWithNames(ctx, "kc-fill", "f@example.org", "Bob B", "Bob", "B")
	if err != nil {
		t.Fatalf("second JITProvisionWithNames: %v", err)
	}
	if u.FirstName != "Bob" || u.LastName != "B" {
		t.Fatalf("expected empty name filled on re-login, got %q / %q", u.FirstName, u.LastName)
	}
}
