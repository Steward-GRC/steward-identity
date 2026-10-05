// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// actorCtx is the context go-grpc-actor's server interceptor hands a handler
// for a trusted caller: the subject, and during act-as the real admin.
func actorCtx(subject, impersonator string) context.Context {
	return grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: subject, Impersonator: impersonator})
}

func lastAuditRow(t *testing.T, pool *pgxpool.Pool, eventType string) (actor uuid.UUID, payload map[string]any) {
	t.Helper()
	evs := auditEvents(t, pool, eventType)
	if len(evs) == 0 {
		t.Fatalf("query audit %s: no event", eventType)
	}
	last := evs[len(evs)-1]
	if last.ActorUserID != nil {
		actor = *last.ActorUserID
	}
	return actor, last.Payload
}

// TestEmitAuditImpersonationAttribution asserts that a mutating store call made
// under impersonation records the real admin as the audit actor and preserves
// the impersonated target under payload.impersonated_user_id, while a call with
// no impersonator keeps the target as the actor and stamps no such attribute.
func TestEmitAuditImpersonationAttribution(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	admin, err := s.JITProvision(ctx, "sub-imp-admin", "admin@e", "Admin")
	if err != nil {
		t.Fatalf("JIT admin: %v", err)
	}
	target, err := s.JITProvision(ctx, "sub-imp-target", "target@e", "Target")
	if err != nil {
		t.Fatalf("JIT target: %v", err)
	}
	grantee, err := s.JITProvision(ctx, "sub-imp-grantee", "grantee@e", "Grantee")
	if err != nil {
		t.Fatalf("JIT grantee: %v", err)
	}
	grantee2, err := s.JITProvision(ctx, "sub-imp-grantee2", "grantee2@e", "Grantee2")
	if err != nil {
		t.Fatalf("JIT grantee2: %v", err)
	}

	// Impersonated: the subject is the target; the admin is the impersonator.
	impCtx := actorCtx(target.ID.String(), admin.ID.String())
	if _, err := s.GrantRole(impCtx, grantee.ID, "author", "Facilities", &target.ID, ""); err != nil {
		t.Fatalf("GrantRole (impersonated): %v", err)
	}
	actor, payload := lastAuditRow(t, pool, "role.granted")
	if actor != admin.ID {
		t.Fatalf("actor_user_id: want admin %s, got %s", admin.ID, actor)
	}
	if got, _ := payload["impersonated_user_id"].(string); got != target.ID.String() {
		t.Fatalf("impersonated_user_id: want target %s, got %q (payload=%v)", target.ID, got, payload)
	}

	// Not impersonated: actor stays the target, no impersonation attribute.
	plainCtx := actorCtx(target.ID.String(), "")
	if _, err := s.GrantRole(plainCtx, grantee2.ID, "author", "Facilities", &target.ID, ""); err != nil {
		t.Fatalf("GrantRole (plain): %v", err)
	}
	actor, payload = lastAuditRow(t, pool, "role.granted")
	if actor != target.ID {
		t.Fatalf("actor_user_id: want target %s, got %s", target.ID, actor)
	}
	if _, ok := payload["impersonated_user_id"]; ok {
		t.Fatalf("impersonated_user_id must be absent without impersonation, got %v", payload["impersonated_user_id"])
	}
}
