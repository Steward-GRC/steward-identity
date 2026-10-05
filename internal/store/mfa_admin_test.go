// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// The admin MFA store ops act on an EXPLICIT target user id supplied by a
// site-admin and record the admin as the audit actor with the target as the
// audit subject (event types "admin.mfa_factor_*"). These tests verify they
// operate on ANY user's row (not the caller's), write the right audit rows, and
// return ErrNotFound when the factor is absent.

func TestAdminTotpDeleteAndRename(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	admin := seedMfaUser(t, s, ctx, "kc-admin-1", "admin1@example.org")
	target := seedMfaUser(t, s, ctx, "kc-target-1", "target1@example.org")

	// Confirmed TOTP enrollment on the TARGET.
	if err := s.UpsertPendingTotp(ctx, target.ID, "sealed"); err != nil {
		t.Fatalf("UpsertPendingTotp: %v", err)
	}
	if err := s.ConfirmTotp(ctx, target.ID); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}

	// AdminTotpFactor reflects the confirmed state, empty label by default.
	confirmedAt, label, err := s.AdminTotpFactor(ctx, target.ID)
	if err != nil {
		t.Fatalf("AdminTotpFactor: %v", err)
	}
	if confirmedAt == nil || label != "" {
		t.Fatalf("want confirmed, empty label; got confirmedAt=%v label=%q", confirmedAt, label)
	}

	// Admin relabels the target's TOTP.
	if err := s.AdminRenameTotp(ctx, target.ID, "Work phone", &admin.ID, ""); err != nil {
		t.Fatalf("AdminRenameTotp: %v", err)
	}
	_, label, err = s.AdminTotpFactor(ctx, target.ID)
	if err != nil {
		t.Fatalf("AdminTotpFactor after rename: %v", err)
	}
	if label != "Work phone" {
		t.Fatalf("label not persisted: got %q", label)
	}

	// Relabel audit: actor = admin, subject = target.
	assertAudit(t, pool, "admin.mfa_factor_relabeled", admin.ID, target.ID,
		map[string]string{"kind": "totp", "label": "Work phone"})

	// Admin resets (removes) the target's TOTP.
	if err := s.AdminDeleteTotp(ctx, target.ID, &admin.ID, ""); err != nil {
		t.Fatalf("AdminDeleteTotp: %v", err)
	}
	if _, _, err := s.AdminTotpFactor(ctx, target.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
	// Re-delete is ErrNotFound.
	if err := s.AdminDeleteTotp(ctx, target.ID, &admin.ID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("re-delete: want ErrNotFound, got %v", err)
	}
	assertAudit(t, pool, "admin.mfa_factor_removed", admin.ID, target.ID,
		map[string]string{"kind": "totp"})
}

func TestAdminTotpFactorNotFound(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	target := seedMfaUser(t, s, ctx, "kc-target-2", "target2@example.org")

	if _, _, err := s.AdminTotpFactor(ctx, target.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no enrollment: want ErrNotFound, got %v", err)
	}
	if err := s.AdminRenameTotp(ctx, target.ID, "x", &target.ID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rename missing: want ErrNotFound, got %v", err)
	}
	if err := s.AdminDeleteTotp(ctx, target.ID, &target.ID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing: want ErrNotFound, got %v", err)
	}
}

func TestAdminWebauthnDeleteAndRename(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	admin := seedMfaUser(t, s, ctx, "kc-admin-3", "admin3@example.org")
	target := seedMfaUser(t, s, ctx, "kc-target-3", "target3@example.org")
	other := seedMfaUser(t, s, ctx, "kc-other-3", "other3@example.org")

	if err := s.InsertWebauthnCredential(ctx, testCred(target.ID, "cred-x")); err != nil {
		t.Fatalf("InsertWebauthnCredential: %v", err)
	}

	// Admin relabels the target's passkey.
	if err := s.AdminRenameWebauthnCredential(ctx, target.ID, "cred-x", "YubiKey 5", &admin.ID, ""); err != nil {
		t.Fatalf("AdminRenameWebauthnCredential: %v", err)
	}
	list, err := s.ListWebauthnCredentials(ctx, target.ID)
	if err != nil || len(list) != 1 || list[0].Label != "YubiKey 5" {
		t.Fatalf("rename not persisted: %+v (err %v)", list, err)
	}
	assertAudit(t, pool, "admin.mfa_factor_relabeled", admin.ID, target.ID,
		map[string]string{"kind": "passkey", "credential_id": "cred-x", "label": "YubiKey 5"})

	// Cross-user scoping: acting on the wrong target misses.
	if err := s.AdminDeleteWebauthnCredential(ctx, other.ID, "cred-x", &admin.ID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-user delete: want ErrNotFound, got %v", err)
	}

	// Admin resets (removes) the target's passkey.
	if err := s.AdminDeleteWebauthnCredential(ctx, target.ID, "cred-x", &admin.ID, ""); err != nil {
		t.Fatalf("AdminDeleteWebauthnCredential: %v", err)
	}
	if list, err := s.ListWebauthnCredentials(ctx, target.ID); err != nil || len(list) != 0 {
		t.Fatalf("after delete: got %d creds, %v", len(list), err)
	}
	if err := s.AdminDeleteWebauthnCredential(ctx, target.ID, "cred-x", &admin.ID, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("re-delete: want ErrNotFound, got %v", err)
	}
	assertAudit(t, pool, "admin.mfa_factor_removed", admin.ID, target.ID,
		map[string]string{"kind": "passkey", "credential_id": "cred-x"})
}

// assertAudit checks that the newest audit event of the given event type
// carries the expected actor (admin) / subject (target) and payload key/values.
func assertAudit(t *testing.T, pool *pgxpool.Pool, eventType string, actor, subject uuid.UUID, payload map[string]string) {
	t.Helper()
	evs := auditEvents(t, pool, eventType)
	if len(evs) == 0 {
		t.Fatalf("query audit %s: no event", eventType)
	}
	last := evs[len(evs)-1]
	var gotActor, gotSubject uuid.UUID
	if last.ActorUserID != nil {
		gotActor = *last.ActorUserID
	}
	if last.TargetUserID != nil {
		gotSubject = *last.TargetUserID
	}
	if gotActor != actor {
		t.Fatalf("%s actor: want %s, got %s", eventType, actor, gotActor)
	}
	if gotSubject != subject {
		t.Fatalf("%s subject: want %s, got %s", eventType, subject, gotSubject)
	}
	got := last.Payload
	for k, v := range payload {
		if gv, _ := got[k].(string); gv != v {
			t.Fatalf("%s payload[%q]: want %q, got %q (payload=%v)", eventType, k, v, gv, got)
		}
	}
}
