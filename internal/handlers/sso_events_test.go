// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// errBreakGlassEmit is a sentinel publish error used to exercise the
// break-glass best-effort emit path (durable row still written).
var errBreakGlassEmit = errors.New("broker down")

// recordedSSOEvent is one PublishSSO call captured by fakeSSOPublisher.
type recordedSSOEvent struct {
	Event string
	Vars  map[string]any
}

// fakeSSOPublisher implements the handlers SSO event seam (PublishSSO) and
// records every event so tests can assert on name + vars. err, when set, is
// returned by PublishSSO to exercise the best-effort/swallow path.
type fakeSSOPublisher struct {
	mu     sync.Mutex
	events []recordedSSOEvent
	err    error
}

func (f *fakeSSOPublisher) PublishSSO(_ context.Context, event string, vars map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, recordedSSOEvent{Event: event, Vars: vars})
	return f.err
}

// Find returns the first recorded event with the given name, or nil.
func (f *fakeSSOPublisher) Find(event string) *recordedSSOEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.events {
		if f.events[i].Event == event {
			return &f.events[i]
		}
	}
	return nil
}

// Count returns how many recorded events have the given name.
func (f *fakeSSOPublisher) Count(event string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for i := range f.events {
		if f.events[i].Event == event {
			n++
		}
	}
	return n
}

// fakeRawPublisher implements the raw mq.Publisher seam so the emitter's wire
// shape (routing key + JSON body) can be asserted without a broker.
type fakeRawPublisher struct {
	routingKey string
	body       []byte
}

func (f *fakeRawPublisher) Publish(_ context.Context, routingKey string, body []byte) error {
	f.routingKey = routingKey
	f.body = body
	return nil
}

// newReadHandlerWithFakePublisher returns a ReadHandler wired to a fresh
// testcontainers store and a fake SSO event publisher, so JIT-emission can be
// asserted. Mirrors newReadHandlerWithStore's skip idiom.
func newReadHandlerWithFakePublisher(t *testing.T) (hintedRead, *store.Store, *fakeSSOPublisher) {
	t.Helper()
	s := newTestStore(t)
	pub := &fakeSSOPublisher{}
	h := hinted(handlers.NewReadHandler(s).WithSSOEventPublisher(pub))
	return h, s, pub
}

// TestSSOEventEmitter_WireShape asserts the emitter marshals {event, vars} onto
// the shared "sso.lifecycle" routing key — the exact envelope Task-31 templates
// consume. Pure unit test (no DB), so it runs everywhere.
func TestSSOEventEmitter_WireShape(t *testing.T) {
	raw := &fakeRawPublisher{}
	em := handlers.NewSSOEventEmitter(raw)

	err := em.PublishSSO(context.Background(), "sso.account_provisioned", map[string]any{
		"email": "new@example.org",
	})
	require.NoError(t, err)
	require.Equal(t, "sso.lifecycle", raw.routingKey)

	var env struct {
		Event string         `json:"event"`
		Vars  map[string]any `json:"vars"`
	}
	require.NoError(t, json.Unmarshal(raw.body, &env))
	require.Equal(t, "sso.account_provisioned", env.Event)
	require.Equal(t, "new@example.org", env.Vars["email"])
}

// TestSSOEventEmitter_NilSafe: a nil wrapped publisher makes PublishSSO a
// no-op, never a panic — the emitter is always safe to wire.
func TestSSOEventEmitter_NilSafe(t *testing.T) {
	em := handlers.NewSSOEventEmitter(nil)
	require.NoError(t, em.PublishSSO(context.Background(), "sso.activated", map[string]any{"domain": "x.example.net"}))
}

// TestJITEmitsAccountProvisioned is the brief's core Task-30 test: a fresh JIT
// create emits exactly one sso.account_provisioned event carrying the correct
// email (no "pending" var — a groupless federated user already has baseline
// access).
func TestJITEmitsAccountProvisioned(t *testing.T) {
	h, _, pub := newReadHandlerWithFakePublisher(t)
	_, err := h.ResolveClaims(
		incomingMDCtx(context.Background(), map[string]string{"x-identity-email": "new@example.org"}),
		&identityv1.ResolveClaimsRequest{ExternalSubject: "sub-new"},
	)
	require.NoError(t, err)

	require.Equal(t, 1, pub.Count("sso.account_provisioned"), "exactly one welcome on fresh create")
	ev := pub.Find("sso.account_provisioned")
	require.NotNil(t, ev)
	require.Equal(t, "new@example.org", ev.Vars["email"])
	require.NotContains(t, ev.Vars, "pending", "the retired pending flag must not be emitted")
}

// TestJITWelcomeNotEmittedOnAdopt: adopting a pre-created local row is NOT a
// fresh provision, so no sso.account_provisioned fires.
func TestJITWelcomeNotEmittedOnAdopt(t *testing.T) {
	h, s, pub := newReadHandlerWithFakePublisher(t)
	ctx := context.Background()
	_, err := s.PreCreateLocalUser(ctx, "adopt.example.org", "adopt@example.org", "Adopt Me")
	require.NoError(t, err)

	_, err = h.ResolveClaims(
		incomingMDCtx(ctx, map[string]string{"x-identity-email": "adopt@example.org"}),
		&identityv1.ResolveClaimsRequest{ExternalSubject: "sub-adopt"},
	)
	require.NoError(t, err)
	require.Equal(t, 0, pub.Count("sso.account_provisioned"), "adopt must not emit the JIT welcome")
}

// TestJITWelcomeNotEmittedOnRepeatLogin: a second ResolveClaims for the same
// subject is a repeat login, not a fresh create, so no welcome re-fires.
func TestJITWelcomeNotEmittedOnRepeatLogin(t *testing.T) {
	h, _, pub := newReadHandlerWithFakePublisher(t)
	ctx := incomingMDCtx(context.Background(), map[string]string{"x-identity-email": "repeat@example.org"})
	req := &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-repeat"}

	_, err := h.ResolveClaims(ctx, req)
	require.NoError(t, err)
	_, err = h.ResolveClaims(ctx, req)
	require.NoError(t, err)

	require.Equal(t, 1, pub.Count("sso.account_provisioned"), "welcome fires once, only on the fresh create")
}

// TestRecordBreakGlassLogin_DurableAndEvent: for a break-glass-ELIGIBLE email,
// the record writes a durable audit row (event_type security.break_glass.login,
// carrying the email) AND publishes user.break_glass.login. No admin auth is
// required — the RPC runs mid-login before the caller has claims.
func TestRecordBreakGlassLogin_DurableAndEvent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Seed an eligible identity (local root → privileged + local credential).
	_, err := s.PreCreateLocalUserRoot(ctx, "root", "root@corp.example.net", "Root")
	require.NoError(t, err)

	pub := &fakeSSOPublisher{}
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).WithSSOEventPublisher(pub)

	_, err = h.RecordBreakGlassLogin(ctx, &identityv1.RecordBreakGlassLoginRequest{
		Email:  "root@corp.example.net",
		Reason: "prod incident",
	})
	require.NoError(t, err)

	// Durable audit row written to the outbox.
	events, err := s.PendingAuditEvents(ctx, 100)
	require.NoError(t, err)
	var found *store.AuditEvent
	for i := range events {
		if events[i].EventType == "security.break_glass.login" {
			found = &events[i]
			break
		}
	}
	require.NotNil(t, found, "durable break-glass audit row must be written")
	require.Equal(t, "root@corp.example.net", found.Payload["email"])

	// Fan-out event published.
	require.Equal(t, 1, pub.Count("user.break_glass.login"))
	ev := pub.Find("user.break_glass.login")
	require.NotNil(t, ev)
	require.Equal(t, "root@corp.example.net", ev.Vars["email"])
}

// TestRecordBreakGlassLogin_RejectsIneligible: an email that is not
// break-glass-eligible (here: an unknown address) is rejected with
// PermissionDenied and produces NO audit row and NO event — closing the
// in-mesh forgery / alert-spam vector.
func TestRecordBreakGlassLogin_RejectsIneligible(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// A plain local user is privileged-less → not_privileged; an unknown email
	// → unknown_user. Both must be rejected. Seed the non-privileged case.
	_, err := s.PreCreateLocalUser(ctx, "bob", "bob@corp.example.net", "Bob")
	require.NoError(t, err)

	pub := &fakeSSOPublisher{}
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).WithSSOEventPublisher(pub)

	for _, email := range []string{"bob@corp.example.net", "nobody@corp.example.net"} {
		_, err := h.RecordBreakGlassLogin(ctx, &identityv1.RecordBreakGlassLoginRequest{Email: email})
		require.Equal(t, codes.PermissionDenied, status.Code(err), "ineligible %q must be rejected", email)
	}

	// No break-glass audit row written (other seeding rows may exist, so we
	// check the specific event type rather than the total count).
	events, err := s.PendingAuditEvents(ctx, 100)
	require.NoError(t, err)
	for _, e := range events {
		require.NotEqual(t, "security.break_glass.login", e.EventType,
			"no break-glass audit row for an ineligible record")
	}
	require.Equal(t, 0, pub.Count("user.break_glass.login"), "no event for an ineligible break-glass record")
}

// TestRecordBreakGlassLogin_EventFailureStillDurable: for an eligible email, a
// publish error is swallowed — the durable audit row is still written and the
// RPC succeeds, so a broker outage never turns into a failed break-glass login.
func TestRecordBreakGlassLogin_EventFailureStillDurable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.PreCreateLocalUserRoot(ctx, "root", "root@corp.example.net", "Root")
	require.NoError(t, err)

	pub := &fakeSSOPublisher{err: errBreakGlassEmit}
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).WithSSOEventPublisher(pub)

	_, err = h.RecordBreakGlassLogin(ctx, &identityv1.RecordBreakGlassLoginRequest{Email: "root@corp.example.net"})
	require.NoError(t, err, "a publish error must not fail the break-glass record")

	n, err := s.CountAuditPending(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(1), "durable audit row written despite emit failure")
}
