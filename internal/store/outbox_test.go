// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

func TestPendingAuditEvents(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// JITProvision emits 2 audit rows.
	_, err := s.JITProvision(ctx, "sub-outbox", "erin@example.org", "Erin")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}

	events, err := s.PendingAuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("PendingAuditEvents: %v", err)
	}
	if len(events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(events))
	}
}

func TestEmitAuditStandalone(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	u, err := s.JITProvision(ctx, "sub-emit", "erin@example.org", "Erin")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	if err := s.EmitAudit(ctx, store.AuditEvent{
		EventType:    "user.login.failure",
		ActorUserID:  nil,
		TargetUserID: &u.ID,
		Payload:      map[string]any{"reason": "disabled"},
	}); err != nil {
		t.Fatalf("EmitAudit: %v", err)
	}

	events, err := s.PendingAuditEvents(ctx, 10)
	if err != nil {
		t.Fatalf("PendingAuditEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.EventType == "user.login.failure" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("emitted event missing from pending: %+v", events)
	}
}
