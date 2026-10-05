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

func newWebauthnTestStore(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	pool := newTestDB(t)
	if pool == nil {
		return nil, nil
	}
	return newStoreFor(t, pool), pool
}

func seedWebauthnUser(t *testing.T, s *store.Store, sub, email string) store.User {
	t.Helper()
	u, err := s.JITProvision(context.Background(), sub, email, "Passkey User")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}
	return u
}

// --- challenge sessions ---

func TestWebauthnSessionSingleUse(t *testing.T) {
	s, _ := newWebauthnTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()
	u := seedWebauthnUser(t, s, "kc-wa-1", "wa1@example.org")

	id, err := s.CreateWebauthnSession(ctx, u.ID, store.WebauthnPurposeRegister, `{"challenge":"abc"}`)
	if err != nil {
		t.Fatalf("CreateWebauthnSession: %v", err)
	}
	data, err := s.ConsumeWebauthnSession(ctx, id, u.ID, store.WebauthnPurposeRegister)
	if err != nil {
		t.Fatalf("ConsumeWebauthnSession: %v", err)
	}
	if data != `{"challenge":"abc"}` {
		t.Fatalf("session data round-trip: got %q", data)
	}
	// Single-use: a second consume of the same session fails.
	if _, err := s.ConsumeWebauthnSession(ctx, id, u.ID, store.WebauthnPurposeRegister); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("reconsume: want ErrNotFound, got %v", err)
	}
}

func TestWebauthnSessionScoping(t *testing.T) {
	s, _ := newWebauthnTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()
	u := seedWebauthnUser(t, s, "kc-wa-2", "wa2@example.org")
	other := seedWebauthnUser(t, s, "kc-wa-3", "wa3@example.org")

	id, err := s.CreateWebauthnSession(ctx, u.ID, store.WebauthnPurposeRegister, `{}`)
	if err != nil {
		t.Fatalf("CreateWebauthnSession: %v", err)
	}
	// Wrong purpose: a register session cannot be spent on an assert.
	if _, err := s.ConsumeWebauthnSession(ctx, id, u.ID, store.WebauthnPurposeAssert); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong purpose: want ErrNotFound, got %v", err)
	}
	// Wrong user: another user cannot spend it.
	if _, err := s.ConsumeWebauthnSession(ctx, id, other.ID, store.WebauthnPurposeRegister); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("wrong user: want ErrNotFound, got %v", err)
	}
	// The mismatched attempts must not have burned the session.
	if _, err := s.ConsumeWebauthnSession(ctx, id, u.ID, store.WebauthnPurposeRegister); err != nil {
		t.Fatalf("consume after mismatched attempts: %v", err)
	}
	// Unknown session id.
	if _, err := s.ConsumeWebauthnSession(ctx, uuid.New(), u.ID, store.WebauthnPurposeRegister); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown session: want ErrNotFound, got %v", err)
	}
}

func TestWebauthnSessionExpiry(t *testing.T) {
	s, pool := newWebauthnTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()
	u := seedWebauthnUser(t, s, "kc-wa-4", "wa4@example.org")

	id, err := s.CreateWebauthnSession(ctx, u.ID, store.WebauthnPurposeAssert, `{}`)
	if err != nil {
		t.Fatalf("CreateWebauthnSession: %v", err)
	}
	// Backdate the session past its TTL.
	if _, err := pool.Exec(ctx,
		`UPDATE webauthn_sessions SET expires_at = now() - interval '1 second' WHERE session_id = $1`, id); err != nil {
		t.Fatalf("backdate session: %v", err)
	}
	if _, err := s.ConsumeWebauthnSession(ctx, id, u.ID, store.WebauthnPurposeAssert); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session: want ErrNotFound, got %v", err)
	}
	// The expired attempt deleted the row (single-use either way).
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM webauthn_sessions WHERE session_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatal("expired session row must be deleted on the consume attempt")
	}
}

func TestWebauthnSessionBeginReplacesLive(t *testing.T) {
	s, _ := newWebauthnTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()
	u := seedWebauthnUser(t, s, "kc-wa-5", "wa5@example.org")

	first, err := s.CreateWebauthnSession(ctx, u.ID, store.WebauthnPurposeRegister, `{"n":1}`)
	if err != nil {
		t.Fatalf("CreateWebauthnSession #1: %v", err)
	}
	second, err := s.CreateWebauthnSession(ctx, u.ID, store.WebauthnPurposeRegister, `{"n":2}`)
	if err != nil {
		t.Fatalf("CreateWebauthnSession #2: %v", err)
	}
	// The restarted ceremony invalidated the first challenge.
	if _, err := s.ConsumeWebauthnSession(ctx, first, u.ID, store.WebauthnPurposeRegister); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("superseded session: want ErrNotFound, got %v", err)
	}
	if data, err := s.ConsumeWebauthnSession(ctx, second, u.ID, store.WebauthnPurposeRegister); err != nil || data != `{"n":2}` {
		t.Fatalf("live session: got %q, %v", data, err)
	}
}

// --- credentials ---

func testCred(userID uuid.UUID, credID string) store.WebauthnCredential {
	return store.WebauthnCredential{
		CredentialID:   credID,
		UserID:         userID,
		PublicKey:      []byte{0xa5, 0x01, 0x02},
		SignCount:      0,
		AAGUID:         make([]byte, 16),
		Transports:     []string{"usb", "nfc"},
		BackupEligible: true,
		BackupState:    false,
		Label:          "test key",
	}
}

func TestWebauthnCredentialInsertListDelete(t *testing.T) {
	s, pool := newWebauthnTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()
	u := seedWebauthnUser(t, s, "kc-wa-6", "wa6@example.org")
	other := seedWebauthnUser(t, s, "kc-wa-7", "wa7@example.org")

	if err := s.InsertWebauthnCredential(ctx, testCred(u.ID, "cred-a")); err != nil {
		t.Fatalf("InsertWebauthnCredential: %v", err)
	}
	// Duplicate credential id — same or DIFFERENT user — is a conflict.
	if err := s.InsertWebauthnCredential(ctx, testCred(u.ID, "cred-a")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate insert: want ErrConflict, got %v", err)
	}
	if err := s.InsertWebauthnCredential(ctx, testCred(other.ID, "cred-a")); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate insert other user: want ErrConflict, got %v", err)
	}

	list, err := s.ListWebauthnCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListWebauthnCredentials: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 credential, got %d", len(list))
	}
	c := list[0]
	if c.CredentialID != "cred-a" || c.Label != "test key" || !c.BackupEligible || c.BackupState {
		t.Fatalf("credential round-trip mismatch: %+v", c)
	}
	if len(c.Transports) != 2 || c.Transports[0] != "usb" || c.Transports[1] != "nfc" {
		t.Fatalf("transports round-trip mismatch: %v", c.Transports)
	}
	if c.LastUsedAt != nil {
		t.Fatal("fresh credential must have nil last_used_at")
	}

	// Enrollment audit event landed in the outbox.
	var audits int
	audits = countKind(t, pool, "user.mfa_factor_enrolled", "passkey")
	if audits != 1 {
		t.Fatalf("want 1 passkey enrollment audit event, got %d", audits)
	}

	// Another user's list is unaffected.
	if list, err := s.ListWebauthnCredentials(ctx, other.ID); err != nil || len(list) != 0 {
		t.Fatalf("other user list: got %d creds, %v", len(list), err)
	}

	// Cross-user delete must not work; own delete does, exactly once.
	if err := s.DeleteWebauthnCredential(ctx, other.ID, "cred-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-user delete: want ErrNotFound, got %v", err)
	}
	if err := s.DeleteWebauthnCredential(ctx, u.ID, "cred-a"); err != nil {
		t.Fatalf("DeleteWebauthnCredential: %v", err)
	}
	if err := s.DeleteWebauthnCredential(ctx, u.ID, "cred-a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("re-delete: want ErrNotFound, got %v", err)
	}
	audits = countKind(t, pool, "user.mfa_factor_removed", "passkey")
	if audits != 1 {
		t.Fatalf("want 1 passkey removal audit event, got %d", audits)
	}
}

func TestWebauthnCredentialUsageUpdate(t *testing.T) {
	s, _ := newWebauthnTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()
	u := seedWebauthnUser(t, s, "kc-wa-8", "wa8@example.org")

	if err := s.InsertWebauthnCredential(ctx, testCred(u.ID, "cred-b")); err != nil {
		t.Fatalf("InsertWebauthnCredential: %v", err)
	}
	if err := s.UpdateWebauthnCredentialUsage(ctx, u.ID, "cred-b", 42); err != nil {
		t.Fatalf("UpdateWebauthnCredentialUsage: %v", err)
	}
	list, err := s.ListWebauthnCredentials(ctx, u.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v", err)
	}
	if list[0].SignCount != 42 {
		t.Fatalf("sign_count: want 42, got %d", list[0].SignCount)
	}
	if list[0].LastUsedAt == nil {
		t.Fatal("last_used_at must be stamped on usage update")
	}
	if err := s.UpdateWebauthnCredentialUsage(ctx, u.ID, "no-such-cred", 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown credential: want ErrNotFound, got %v", err)
	}
}

func TestWebauthnDeleteAllCredentials(t *testing.T) {
	s, _ := newWebauthnTestStore(t)
	if s == nil {
		return
	}
	ctx := context.Background()
	u := seedWebauthnUser(t, s, "kc-wa-9", "wa9@example.org")

	if _, err := s.DeleteAllWebauthnCredentials(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete-all with none: want ErrNotFound, got %v", err)
	}
	if err := s.InsertWebauthnCredential(ctx, testCred(u.ID, "cred-c")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := s.InsertWebauthnCredential(ctx, testCred(u.ID, "cred-d")); err != nil {
		t.Fatalf("insert: %v", err)
	}
	n, err := s.DeleteAllWebauthnCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("DeleteAllWebauthnCredentials: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 removed, got %d", n)
	}
	if list, err := s.ListWebauthnCredentials(ctx, u.ID); err != nil || len(list) != 0 {
		t.Fatalf("list after delete-all: got %d, %v", len(list), err)
	}
}

func countKind(t *testing.T, pool *pgxpool.Pool, eventType, kind string) int {
	t.Helper()
	n := 0
	for _, e := range auditEvents(t, pool, eventType) {
		if e.Payload["kind"] == kind {
			n++
		}
	}
	return n
}
