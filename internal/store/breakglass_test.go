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
	if len(active) != 1 || active[0] != "POL-IT-1" {
		t.Fatalf("active: %v", active)
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
