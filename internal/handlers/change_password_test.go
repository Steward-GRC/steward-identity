// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

const (
	cpCurrent = "current-pw-for-tests"
	cpNew     = "new-pw-for-tests-longer"
)

// fakeChanger stands in for the Kratos public password change.
type fakeChanger struct {
	mu    sync.Mutex
	calls []struct{ identifier, current, next string }
	err   error
}

func (f *fakeChanger) ChangePassword(_ context.Context, identifier, current, next string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, struct{ identifier, current, next string }{identifier, current, next})
	return f.err
}

func localUserWithKratos(t *testing.T, s *store.Store, fk *fakeKratos) store.User {
	t.Helper()
	u, err := s.PreCreateLocalUser(context.Background(), "dana", "dana@example.org", "Dana")
	require.NoError(t, err)
	fk.add(kratos.Account{Username: "dana", Email: "dana@example.org", Name: "Dana"}, cpCurrent)
	return u
}

func auditEvents(t *testing.T, s *store.Store, eventType string) []store.AuditEvent {
	t.Helper()
	evs, err := s.PendingAuditEvents(context.Background(), 200)
	require.NoError(t, err)
	var out []store.AuditEvent
	for _, e := range evs {
		if e.EventType == eventType {
			out = append(out, e)
		}
	}
	return out
}

func TestChangeMyPassword_ChangesTheCallersOwnPasswordAndAuditsItWithoutSecrets(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u := localUserWithKratos(t, s, fk)
	ch := &fakeChanger{}
	h := handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(ch)

	resp, err := h.ChangeMyPassword(passwordCallerCtx(u.ID.String()), &identityv1.ChangeMyPasswordRequest{CurrentPassword: cpCurrent, NewPassword: cpNew})

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, ch.calls, 1)
	require.Equal(t, "dana@example.org", ch.calls[0].identifier, "the caller's own sign-in identifier")
	require.Equal(t, cpCurrent, ch.calls[0].current)
	require.Equal(t, cpNew, ch.calls[0].next)

	evs := auditEvents(t, s, "user.password.changed")
	require.Len(t, evs, 1)
	require.NotNil(t, evs[0].ActorUserID)
	require.Equal(t, u.ID, *evs[0].ActorUserID)
	require.NotNil(t, evs[0].TargetUserID)
	require.Equal(t, u.ID, *evs[0].TargetUserID)
	require.Equal(t, "self_service", evs[0].Payload["method"])
	require.NotContains(t, fmt.Sprint(evs[0].Payload), cpCurrent)
	require.NotContains(t, fmt.Sprint(evs[0].Payload), cpNew)
}

func TestChangeMyPassword_NeedsACallerAndBothPasswords(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u := localUserWithKratos(t, s, fk)
	ch := &fakeChanger{}
	h := handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(ch)

	_, err := h.ChangeMyPassword(context.Background(), &identityv1.ChangeMyPasswordRequest{CurrentPassword: cpCurrent, NewPassword: cpNew})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	for _, req := range []*identityv1.ChangeMyPasswordRequest{
		{NewPassword: cpNew}, {CurrentPassword: cpCurrent}, {},
	} {
		_, err = h.ChangeMyPassword(passwordCallerCtx(u.ID.String()), req)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	require.Empty(t, ch.calls, "nothing reaches the sign-in service")
}

func TestChangeMyPassword_AWrongCurrentPasswordIsCodedAndAudited(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u := localUserWithKratos(t, s, fk)
	h := handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(&fakeChanger{err: kratos.ErrWrongPassword})

	_, err := h.ChangeMyPassword(passwordCallerCtx(u.ID.String()), &identityv1.ChangeMyPasswordRequest{CurrentPassword: "nope", NewPassword: cpNew})

	requireCodedInvalid(t, err, errcodes.CodeCurrentPasswordWrong)
	require.Empty(t, auditEvents(t, s, "user.password.changed"))
	failed := auditEvents(t, s, "user.password.change_failed")
	require.Len(t, failed, 1)
	require.Equal(t, "wrong_current_password", failed[0].Payload["reason"])
	require.NotContains(t, fmt.Sprint(failed[0].Payload), "nope")
	require.NotContains(t, fmt.Sprint(failed[0].Payload), cpNew)
}

func TestChangeMyPassword_AWeakNewPasswordIsCoded(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u := localUserWithKratos(t, s, fk)
	h := handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(&fakeChanger{err: fmt.Errorf("policy: %w", kratos.ErrWeakPassword)})

	_, err := h.ChangeMyPassword(passwordCallerCtx(u.ID.String()), &identityv1.ChangeMyPasswordRequest{CurrentPassword: cpCurrent, NewPassword: "abc"})

	requireCodedInvalid(t, err, errcodes.CodePasswordTooWeak)
	require.Empty(t, auditEvents(t, s, "user.password.changed"))
	require.Equal(t, "weak_new_password", auditEvents(t, s, "user.password.change_failed")[0].Payload["reason"])
}

func TestChangeMyPassword_AnSSOOnlyAccountHasNoPasswordToChange(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, err := s.JITProvision(context.Background(), "sub-sso-only", "sam@example.org", "Sam")
	require.NoError(t, err)
	ch := &fakeChanger{}
	h := handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(ch)

	_, err = h.ChangeMyPassword(passwordCallerCtx(u.ID.String()), &identityv1.ChangeMyPasswordRequest{CurrentPassword: cpCurrent, NewPassword: cpNew})

	requireCoded(t, err, errcodes.CodeNoLocalPassword)
	require.Empty(t, ch.calls)
}

func TestChangeMyPassword_ALocalAccountWithNoSignInIdentityHasNoPassword(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u, err := s.PreCreateLocalUser(context.Background(), "lee", "lee@example.org", "Lee")
	require.NoError(t, err)
	ch := &fakeChanger{}
	h := handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(ch)

	_, err = h.ChangeMyPassword(passwordCallerCtx(u.ID.String()), &identityv1.ChangeMyPasswordRequest{CurrentPassword: cpCurrent, NewPassword: cpNew})

	requireCoded(t, err, errcodes.CodeNoLocalPassword)
	require.Empty(t, ch.calls)
}

func TestChangeMyPassword_IsRefusedWhileActingAsAnotherUser(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u := localUserWithKratos(t, s, fk)
	ch := &fakeChanger{}
	h := handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(ch)

	_, err := h.ChangeMyPassword(actingAsCtx(u.ID.String(), "00000000-0000-0000-0000-0000000000ad"),
		&identityv1.ChangeMyPasswordRequest{CurrentPassword: cpCurrent, NewPassword: cpNew})

	requireActAsForbidden(t, err)
	require.Empty(t, ch.calls)
}

func TestChangeMyPassword_FailsClosedWhenKratosCannotAnswer(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	u := localUserWithKratos(t, s, fk)
	req := &identityv1.ChangeMyPasswordRequest{CurrentPassword: cpCurrent, NewPassword: cpNew}

	// Not configured at all.
	_, err := handlers.NewReadHandler(s).ChangeMyPassword(passwordCallerCtx(u.ID.String()), req)
	requireCoded(t, err, errcodes.CodePasswordChangeUnavailable)
	_, err = handlers.NewReadHandler(s).WithSignIn(fk).ChangeMyPassword(passwordCallerCtx(u.ID.String()), req)
	requireCoded(t, err, errcodes.CodePasswordChangeUnavailable)

	// Configured but down: the cause stays server-side.
	down := errors.New("dial tcp 192.0.2.1:4433: connection refused " + cpCurrent)
	_, err = handlers.NewReadHandler(s).WithSignIn(fk).WithPasswordChanger(&fakeChanger{err: down}).ChangeMyPassword(passwordCallerCtx(u.ID.String()), req)
	requireCoded(t, err, errcodes.CodePasswordChangeUnavailable)
	require.False(t, strings.Contains(err.Error(), cpCurrent), "no secret in the answer")
	require.Empty(t, auditEvents(t, s, "user.password.changed"))
}

// passwordCallerCtx is a call forwarded for the signed-in user id.
func passwordCallerCtx(id string) context.Context {
	return grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: id})
}

// requireCodedInvalid asserts err is the coded InvalidArgument error code, with
// its ErrorInfo symbol and user-safe message.
func requireCodedInvalid(t *testing.T, err error, code int) {
	t.Helper()
	e, ok := errcodes.Registry().Describe(code)
	require.True(t, ok, "code %d is registered", code)
	st, ok := status.FromError(err)
	require.True(t, ok, "a gRPC status, got %T", err)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, e.Message, st.Message())
	info, ok := apperrgrpc.FromStatus(st)
	require.True(t, ok)
	require.Equal(t, e.Symbol, info.Symbol)
	require.Equal(t, code, info.Code)
}
