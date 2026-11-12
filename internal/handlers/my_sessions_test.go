// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

func asUser(id string) context.Context {
	return grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: id})
}

func TestListMySessions_ListsTheCallersActiveSessionsAndMarksTheCurrentOne(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, id := seedSessions(t, s, fk) // two active, one ended
	other, _ := s.PreCreateLocalUser(context.Background(), "erin", "erin@example.org", "Erin")
	oid := fk.add(kratos.Account{Username: "erin", Email: "erin@example.org", Name: "Erin"}, "pw")
	fk.addSession(oid, true)
	_ = other
	h := handlers.NewReadHandler(s).WithSignIn(fk)

	current := fk.sessions[id][1].ID
	resp, err := h.ListMySessions(asUser(u.ID.String()), &identityv1.ListMySessionsRequest{CurrentSessionId: current})
	if err != nil {
		t.Fatalf("ListMySessions: %v", err)
	}
	if len(resp.GetSessions()) != 2 {
		t.Fatalf("want the 2 active sessions of the caller, got %d", len(resp.GetSessions()))
	}
	marked := 0
	for _, ss := range resp.GetSessions() {
		if !ss.GetActive() || ss.GetUserId() != u.ID.String() {
			t.Fatalf("session: %+v", ss)
		}
		if ss.GetCurrent() {
			marked++
			if ss.GetSessionId() != current {
				t.Fatalf("marked %q, want %q", ss.GetSessionId(), current)
			}
		}
	}
	if marked != 1 {
		t.Fatalf("want exactly one current session, got %d", marked)
	}

	// No current id supplied: none is marked.
	resp, err = h.ListMySessions(asUser(u.ID.String()), &identityv1.ListMySessionsRequest{})
	if err != nil {
		t.Fatalf("ListMySessions: %v", err)
	}
	for _, ss := range resp.GetSessions() {
		if ss.GetCurrent() {
			t.Fatal("a session was marked current without a current session id")
		}
	}
}

func TestListMySessions_NeedsACallerAndFailsClosed(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, _ := seedSessions(t, s, fk)
	if _, err := handlers.NewReadHandler(s).WithSignIn(fk).ListMySessions(context.Background(), &identityv1.ListMySessionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no caller: want Unauthenticated, got %v", err)
	}
	_, err := handlers.NewReadHandler(s).ListMySessions(asUser(u.ID.String()), &identityv1.ListMySessionsRequest{})
	requireCoded(t, err, errcodes.CodeSessionsUnavailable)
	failing := newFakeKratos()
	failing.err = context.DeadlineExceeded
	_, err = handlers.NewReadHandler(s).WithSignIn(failing).ListMySessions(asUser(u.ID.String()), &identityv1.ListMySessionsRequest{})
	requireCoded(t, err, errcodes.CodeSessionsUnavailable)
}

func TestRevokeMySession_RevokesAnotherSessionOfTheCallerAndAudits(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, id := seedSessions(t, s, fk)
	h := handlers.NewReadHandler(s).WithSignIn(fk)

	current, target := fk.sessions[id][0].ID, fk.sessions[id][1].ID
	resp, err := h.RevokeMySession(asUser(u.ID.String()), &identityv1.RevokeMySessionRequest{SessionId: target, CurrentSessionId: current})
	if err != nil || resp.GetRevoked() != 1 {
		t.Fatalf("RevokeMySession: %v %v", resp, err)
	}
	if fk.sessions[id][1].Active || !fk.sessions[id][0].Active {
		t.Fatal("the wrong session was revoked")
	}
	if n := countAudit(t, s, "session.revoked", u.ID); n != 1 {
		t.Fatalf("session.revoked events: got %d, want 1", n)
	}
	// Already ended: nothing more to revoke, no second audit event.
	resp, err = h.RevokeMySession(asUser(u.ID.String()), &identityv1.RevokeMySessionRequest{SessionId: target, CurrentSessionId: current})
	if err != nil || resp.GetRevoked() != 0 {
		t.Fatalf("second revoke: %v %v", resp, err)
	}
	if n := countAudit(t, s, "session.revoked", u.ID); n != 1 {
		t.Fatalf("session.revoked events after a no-op: got %d, want 1", n)
	}
}

func TestRevokeMySession_RefusesTheCurrentSessionAndAnyoneElses(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, id := seedSessions(t, s, fk)
	_, _ = s.PreCreateLocalUser(context.Background(), "erin", "erin@example.org", "Erin")
	oid := fk.add(kratos.Account{Username: "erin", Email: "erin@example.org", Name: "Erin"}, "pw")
	theirs := fk.addSession(oid, true)
	h := handlers.NewReadHandler(s).WithSignIn(fk)
	mine := asUser(u.ID.String())
	current := fk.sessions[id][0].ID

	if _, err := h.RevokeMySession(mine, &identityv1.RevokeMySessionRequest{SessionId: current, CurrentSessionId: current}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("current session: want FailedPrecondition, got %v", err)
	}
	if !fk.sessions[id][0].Active {
		t.Fatal("the current session was revoked")
	}
	if _, err := h.RevokeMySession(mine, &identityv1.RevokeMySessionRequest{SessionId: theirs, CurrentSessionId: current}); status.Code(err) != codes.NotFound {
		t.Fatalf("someone else's session: want NotFound, got %v", err)
	}
	if !fk.sessions[oid][0].Active {
		t.Fatal("another person's session was revoked")
	}
	if _, err := h.RevokeMySession(mine, &identityv1.RevokeMySessionRequest{SessionId: "5f0c1d2e-0000-4000-8000-000000000001", CurrentSessionId: current}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session: want NotFound, got %v", err)
	}
	if _, err := h.RevokeMySession(mine, &identityv1.RevokeMySessionRequest{CurrentSessionId: current}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no session id: want InvalidArgument, got %v", err)
	}
	// Without knowing which session is current the call cannot promise to spare it.
	if _, err := h.RevokeMySession(mine, &identityv1.RevokeMySessionRequest{SessionId: fk.sessions[id][1].ID}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no current session id: want InvalidArgument, got %v", err)
	}
	if _, err := h.RevokeMySession(context.Background(), &identityv1.RevokeMySessionRequest{SessionId: current, CurrentSessionId: current}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no caller: want Unauthenticated, got %v", err)
	}
}

func TestRevokeMySession_FailsClosed(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, id := seedSessions(t, s, fk)
	current, target := fk.sessions[id][0].ID, fk.sessions[id][1].ID
	req := &identityv1.RevokeMySessionRequest{SessionId: target, CurrentSessionId: current}

	_, err := handlers.NewReadHandler(s).RevokeMySession(asUser(u.ID.String()), req)
	requireCoded(t, err, errcodes.CodeSessionRevokeUnavailable)
	failing := newFakeKratos()
	failing.err = context.DeadlineExceeded
	_, err = handlers.NewReadHandler(s).WithSignIn(failing).RevokeMySession(asUser(u.ID.String()), req)
	requireCoded(t, err, errcodes.CodeSessionRevokeUnavailable)
}
