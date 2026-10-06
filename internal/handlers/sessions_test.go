// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// requireCoded asserts err carries code end to end: the gRPC code, the
// ErrorInfo symbol, code and domain, and the user-safe message.
func requireCoded(t *testing.T, err error, code int) {
	t.Helper()
	e, ok := errcodes.Registry().Describe(code)
	if !ok {
		t.Fatalf("code %d is not registered", code)
	}
	if err == nil {
		t.Fatalf("want coded error %s, got nil (the surface reported success)", e.Symbol)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("want a gRPC status, got %T: %v", err, err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v (%v)", st.Code(), err)
	}
	if st.Message() != e.Message {
		t.Fatalf("want registry message %q, got %q", e.Message, st.Message())
	}
	info, ok := apperrgrpc.FromStatus(st)
	if !ok || info.Symbol != e.Symbol || info.Code != code || info.Domain != "identity" {
		t.Fatalf("ErrorInfo: got %+v, want %s/%d/identity", info, e.Symbol, code)
	}
}

// seedSessions creates a local user Carol with a Kratos identity holding two
// active sessions and one ended one.
func seedSessions(t *testing.T, s *store.Store, fk *fakeKratos) (store.User, string) {
	t.Helper()
	u, err := s.PreCreateLocalUser(context.Background(), "carol", "carol@example.org", "Carol")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	id := fk.add(kratos.Account{Username: "carol", Email: "carol@example.org", Name: "Carol"}, "pw")
	fk.addSession(id, true)
	fk.addSession(id, true)
	fk.addSession(id, false)
	return u, id
}

func TestListUserSessionsReadsKratos(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-sr-list-admin", "alice@example.org", "Alice")
	u, _ := seedSessions(t, s, fk)
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	resp, err := h.ListUserSessions(adminCtx(admin.ID.String()), &identityv1.ListUserSessionsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(resp.Sessions) != 3 {
		t.Fatalf("sessions: got %d, want 3", len(resp.Sessions))
	}
	active := 0
	for _, ss := range resp.Sessions {
		if ss.UserId != u.ID.String() || ss.UserAgent != "Example Browser/1.0" || ss.ClientIp != "203.0.113.7" {
			t.Fatalf("session: %+v", ss)
		}
		if ss.Active {
			active++
		}
	}
	if active != 2 {
		t.Fatalf("active: got %d, want 2", active)
	}
}

func TestRevokeUserSessionsRevokesInKratosAndAudits(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-sr-revoke-admin", "alice@example.org", "Alice")
	u, id := seedSessions(t, s, fk)
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	resp, err := h.RevokeUserSessions(adminCtx(admin.ID.String()), &identityv1.RevokeUserSessionsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	if resp.Revoked != 2 {
		t.Fatalf("revoked: got %d, want 2", resp.Revoked)
	}
	for _, ss := range fk.sessions[id] {
		if ss.Active {
			t.Fatal("a session is still active in Kratos")
		}
	}
	if n := countAudit(t, s, "session.revoked", u.ID); n != 1 {
		t.Fatalf("session.revoked events: got %d, want 1", n)
	}
}

func TestRevokeSessionRevokesOne(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "sub-sr-one-admin", "alice@example.org", "Alice")
	_, id := seedSessions(t, s, fk)
	h := handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(fk)

	sid := fk.sessions[id][0].ID
	resp, err := h.RevokeSession(adminCtx(admin.ID.String()), &identityv1.RevokeSessionRequest{SessionId: sid})
	if err != nil || resp.Revoked != 1 {
		t.Fatalf("RevokeSession: %v %v", resp, err)
	}
	resp, err = h.RevokeSession(adminCtx(admin.ID.String()), &identityv1.RevokeSessionRequest{SessionId: sid})
	if err != nil || resp.Revoked != 0 {
		t.Fatalf("a second revoke of the same session revokes nothing: %v %v", resp, err)
	}
}

func TestRevokeMySessionsRevokesTheCaller(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, _ := seedSessions(t, s, fk)
	h := handlers.NewReadHandler(s).WithSignIn(fk)

	ctx := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: u.ID.String()})
	resp, err := h.RevokeMySessions(ctx, &identityv1.RevokeMySessionsRequest{})
	if err != nil || resp.Revoked != 2 {
		t.Fatalf("RevokeMySessions: %v %v", resp, err)
	}
	if _, err := h.RevokeMySessions(context.Background(), &identityv1.RevokeMySessionsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no caller: want Unauthenticated, got %v", err)
	}
}

// Without Kratos, or with Kratos failing, the session surfaces say so
// instead of answering an empty list or "revoked: 0".
func TestSessionSurfacesFailClosed(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "sub-sr-fc-admin", "alice@example.org", "Alice")
	u, err := s.PreCreateLocalUser(context.Background(), "dave", "dave@example.org", "Dave")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	failing := newFakeKratos()
	failing.err = errors.New("kratos: connection refused")
	for name, h := range map[string]*handlers.AdminHandler{
		"no kratos":      handlers.NewAdminHandler(s, testAdminAuth()),
		"kratos failing": handlers.NewAdminHandler(s, testAdminAuth()).WithSignIn(failing),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := adminCtx(admin.ID.String())
			_, err := h.ListUserSessions(ctx, &identityv1.ListUserSessionsRequest{UserId: u.ID.String()})
			requireCoded(t, err, errcodes.CodeSessionsUnavailable)
			_, err = h.RevokeUserSessions(ctx, &identityv1.RevokeUserSessionsRequest{UserId: u.ID.String()})
			requireCoded(t, err, errcodes.CodeSessionRevokeUnavailable)
			_, err = h.RevokeSession(ctx, &identityv1.RevokeSessionRequest{SessionId: "5f0c1d2e-0000-4000-8000-000000000001"})
			requireCoded(t, err, errcodes.CodeSessionRevokeUnavailable)
		})
	}
	mine := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: u.ID.String()})
	_, err = handlers.NewReadHandler(s).RevokeMySessions(mine, &identityv1.RevokeMySessionsRequest{})
	requireCoded(t, err, errcodes.CodeSessionRevokeUnavailable)
}
