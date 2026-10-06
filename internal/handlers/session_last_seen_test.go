// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

func TestGetUserWithASessionRecordsItAsSeen(t *testing.T) {
	s := newTestStore(t)
	u, err := s.PreCreateLocalUser(context.Background(), "frank", "frank@example.org", "Frank")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	h := handlers.NewReadHandler(s)
	sid := uuid.New()

	if _, err := h.GetUser(context.Background(), &identityv1.GetUserRequest{UserId: u.ID.String(), SessionId: sid.String()}); err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	seen, err := s.SessionsLastSeen(context.Background(), []uuid.UUID{sid})
	if err != nil {
		t.Fatalf("SessionsLastSeen: %v", err)
	}
	if at, ok := seen[sid]; !ok || time.Since(at) > time.Minute {
		t.Fatalf("session not recorded as seen: %v %v", at, ok)
	}
}

func TestGetUserWithoutASessionRecordsNothing(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.PreCreateLocalUser(context.Background(), "gina", "gina@example.org", "Gina")
	h := handlers.NewReadHandler(s)

	if _, err := h.GetUser(context.Background(), &identityv1.GetUserRequest{UserId: u.ID.String()}); err != nil {
		t.Fatalf("GetUser: %v", err)
	}
}

func TestGetUserRejectsAMalformedSessionID(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.PreCreateLocalUser(context.Background(), "hank", "hank@example.org", "Hank")
	h := handlers.NewReadHandler(s)

	_, err := h.GetUser(context.Background(), &identityv1.GetUserRequest{UserId: u.ID.String(), SessionId: "not-a-session"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

func TestListUserSessionsCarriesLastSeen(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-sr-seen-admin", "alice@example.org", "Alice")
	u, id := seedSessions(t, s, fk)
	seenID := fk.sessions[id][0].ID
	if _, err := handlers.NewReadHandler(s).GetUser(context.Background(),
		&identityv1.GetUserRequest{UserId: u.ID.String(), SessionId: seenID}); err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	resp, err := h.ListUserSessions(adminCtx(admin.ID.String()), &identityv1.ListUserSessionsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	for _, ss := range resp.Sessions {
		if ss.SessionId != seenID {
			if ss.LastSeenAt != "" {
				t.Fatalf("a session never seen has last_seen_at %q", ss.LastSeenAt)
			}
			continue
		}
		at, err := time.Parse(time.RFC3339, ss.LastSeenAt)
		if err != nil || time.Since(at) > time.Minute {
			t.Fatalf("last_seen_at %q: %v", ss.LastSeenAt, err)
		}
	}
}
