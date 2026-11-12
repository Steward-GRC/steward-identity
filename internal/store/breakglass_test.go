// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBreakGlass_GrantAndActive(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-bg-grant", "bg@e", "BG")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	exp, err := s.GrantBreakGlass(ctx, u.ID, "POL-IT-1", "investigating incident", 15, nil)
	if err != nil || !exp.After(time.Now()) {
		t.Fatalf("grant: %v exp=%v", err, exp)
	}

	active, err := s.ActiveBreakGlass(ctx, u.ID.String())
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(active) != 1 || active[0].PolicyNumber != "POL-IT-1" {
		t.Fatalf("active: %v", active)
	}
	if !active[0].ExpiresAt.Equal(exp) {
		t.Fatalf("active expiry %v, want the grant's %v", active[0].ExpiresAt, exp)
	}

	// Emits a high-severity audit event into the audit buffer.
	count := 0
	for _, e := range auditEvents(t, pool, "policy.break_glass_revealed") {
		if e.TargetUserID != nil && *e.TargetUserID == u.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 break-glass audit event, got %d", count)
	}
}

// A second reveal of the same policy extends the window; the answer carries
// the later expiry once, and another person's grant is never reported.
func TestBreakGlass_ActiveReportsTheLatestExpiryPerPolicyAndOnlyTheCallers(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, _ := s.JITProvision(ctx, "sub-bg-latest", "bgl@e", "BGL")
	other, _ := s.JITProvision(ctx, "sub-bg-other", "bgo@e", "BGO")

	if _, err := s.GrantBreakGlass(ctx, u.ID, "POL-IT-2", "first", 5, nil); err != nil {
		t.Fatalf("grant: %v", err)
	}
	later, err := s.GrantBreakGlass(ctx, u.ID, "POL-IT-2", "second", 30, nil)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if _, err := s.GrantBreakGlass(ctx, other.ID, "POL-IT-3", "theirs", 30, nil); err != nil {
		t.Fatalf("grant: %v", err)
	}
	active, err := s.ActiveBreakGlass(ctx, u.ID.String())
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(active) != 1 || active[0].PolicyNumber != "POL-IT-2" || !active[0].ExpiresAt.Equal(later) {
		t.Fatalf("want one grant on POL-IT-2 ending %v, got %+v", later, active)
	}
}

func TestBreakGlass_Expired(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-bg-exp", "bge@e", "BGE")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	// A grant with a negative duration is already expired.
	if _, err := s.GrantBreakGlass(ctx, u.ID, "POL-IT-9", "incident", -1, nil); err != nil {
		t.Fatalf("grant: %v", err)
	}
	active, err := s.ActiveBreakGlass(ctx, u.ID.String())
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected no active grants (expired), got %v", active)
	}
}

func TestBreakGlass_UserNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	if _, err := s.GrantBreakGlass(context.Background(), uuid.New(), "POL-X", "reason", 15, nil); err == nil {
		t.Fatal("expected error granting break-glass to a non-existent user")
	}
}

func TestBreakGlass_Sweep(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-bg-sweep", "bgs@e", "BGS")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	// An already-expired grant is purged once past the retention window.
	if _, err := s.GrantBreakGlass(ctx, u.ID, "POL-OLD", "reason", -1, nil); err != nil {
		t.Fatalf("grant: %v", err)
	}
	n, err := s.SweepBreakGlass(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 swept grant, got %d", n)
	}
}
