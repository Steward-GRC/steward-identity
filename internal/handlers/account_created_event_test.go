// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// capturingAcctPub records every publish so account.created emissions can be
// asserted across all creation routes without a broker.
type capturingAcctPub struct {
	mu    sync.Mutex
	calls []capturedMsg
}

type capturedMsg struct {
	routingKey string
	body       []byte
}

func (p *capturingAcctPub) Publish(_ context.Context, routingKey string, body []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, capturedMsg{routingKey, append([]byte(nil), body...)})
	return nil
}

// accountCreatedUserIDs returns the user ids from every account.created event
// captured (ignoring any other routing keys published on the same seam).
func (p *capturingAcctPub) accountCreatedUserIDs(t *testing.T) []string {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for _, c := range p.calls {
		if c.routingKey != "account.created" {
			continue
		}
		var evt struct {
			EventType string `json:"event_type"`
			UserID    string `json:"user_id"`
		}
		require.NoError(t, json.Unmarshal(c.body, &evt))
		require.Equal(t, "account.created", evt.EventType)
		ids = append(ids, evt.UserID)
	}
	return ids
}

// TestCreateLocalUser_EmitsAccountCreated: an admin local-account create emits
// exactly one account.created carrying the new user's id.
func TestCreateLocalUser_EmitsAccountCreated(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	admin, _ := s.JITProvision(context.Background(), "kc-acct-clu", "clu-acct@e", "CluA")
	auth := testAdminAuth()
	pub := &capturingAcctPub{}
	h := handlers.NewAdminHandler(s, auth).WithSignIn(fk).WithAccountCreatedPublisher(pub)

	resp, err := h.CreateLocalUser(adminCtx(admin.ID.String()), &identityv1.CreateLocalUserRequest{
		Username: "acctnew",
		Email:    "acctnew@example.com",
		Name:     "Acct New",
		Password: "Passw0rd!",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())

	ids := pub.accountCreatedUserIDs(t)
	require.Equal(t, []string{resp.GetUser().GetId()}, ids,
		"CreateLocalUser must emit exactly one account.created for the new user")
}

// TestBootstrapRoot_EmitsAccountCreatedOnceThenNoOp: /setup bootstrap emits one
// account.created on the genuine first create; the idempotent no-op re-run
// (root already exists) must NOT re-emit.
func TestBootstrapRoot_EmitsAccountCreatedOnceThenNoOp(t *testing.T) {
	s := newTestStore(t)
	fk := newFakeKratos()
	pub := &capturingAcctPub{}
	h := hinted(handlers.NewReadHandler(s).WithSignIn(fk).WithAccountCreatedPublisher(pub))

	resp, err := h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "rootadmin", Email: "root@example.com", Password: "Sup3rSecret!", Name: "Root Admin",
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	require.Equal(t, []string{resp.GetUser().GetId()}, pub.accountCreatedUserIDs(t),
		"first BootstrapRoot must emit one account.created")

	// Second call is a no-op (root already exists) and must not re-emit.
	_, err = h.BootstrapRoot(context.Background(), &identityv1.BootstrapRootRequest{
		Username: "rootadmin2", Email: "root2@example.com", Password: "Sup3rSecret!", Name: "Root Admin 2",
	})
	require.NoError(t, err)
	require.Len(t, pub.accountCreatedUserIDs(t), 1,
		"the already-bootstrapped no-op must not emit a second account.created")
}

// TestResolveClaims_JITCreate_EmitsAccountCreated: a fresh federated (subject)
// JIT create emits one account.created; a repeat login for the same subject
// (no new create) must NOT re-emit.
func TestResolveClaims_JITCreate_EmitsAccountCreated(t *testing.T) {
	s := newTestStore(t)
	pub := &capturingAcctPub{}
	h := hinted(handlers.NewReadHandler(s).WithAccountCreatedPublisher(pub))

	ctx := incomingMDCtx(context.Background(), map[string]string{
		"x-identity-email": "jit.new@corp.example.com",
		"x-identity-name":  "Jit New",
	})
	resp, err := h.ResolveClaims(ctx, &identityv1.ResolveClaimsRequest{ExternalSubject: "kc-acct-jit-1"})
	require.NoError(t, err)
	require.Equal(t, []string{resp.GetUser().GetId()}, pub.accountCreatedUserIDs(t),
		"a fresh JIT create must emit one account.created")

	// Repeat login: same subject now exists -> no store create -> no re-emit.
	_, err = h.ResolveClaims(context.Background(), &identityv1.ResolveClaimsRequest{ExternalSubject: "kc-acct-jit-1"})
	require.NoError(t, err)
	require.Len(t, pub.accountCreatedUserIDs(t), 1,
		"a repeat login for an existing user must not re-emit account.created")
}

// TestResolveClaims_Adopt_DoesNotEmit: adopting a pre-created local row links an
// ALREADY-EXISTING account, so it must NOT emit account.created (the account
// was already welcomed when it was pre-created).
func TestResolveClaims_Adopt_DoesNotEmit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	_, err := s.PreCreateLocalUser(ctx, "adopt.reader", "adopt.reader@corp.example.com", "Adopt Reader")
	require.NoError(t, err)

	pub := &capturingAcctPub{}
	h := hinted(handlers.NewReadHandler(s).WithAccountCreatedPublisher(pub))

	adoptCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email": "adopt.reader@corp.example.com",
		"x-identity-name":  "Adopt Reader",
	})
	_, err = h.ResolveClaims(adoptCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "kc-acct-adopt-1"})
	require.NoError(t, err)
	require.Empty(t, pub.accountCreatedUserIDs(t),
		"adopting a pre-created local user must not emit account.created")
}

// TestJitProvisionByEmail_EmitsAccountCreated: a fresh by-email federated create
// emits one account.created; an existing email does not.
func TestJitProvisionByEmail_EmitsAccountCreated(t *testing.T) {
	s := newTestStore(t)
	pub := &capturingAcctPub{}
	h := hinted(handlers.NewReadHandler(s).WithAccountCreatedPublisher(pub))
	ctx := context.Background()

	resp, err := h.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email: "byemail.new@corp.example.com", FirstName: "By", LastName: "Email",
	})
	require.NoError(t, err)
	require.Equal(t, []string{resp.GetUser().GetId()}, pub.accountCreatedUserIDs(t),
		"a fresh JIT-by-email create must emit one account.created")

	// Idempotent hit on the existing email -> no re-emit.
	_, err = h.JitProvisionByEmail(ctx, &identityv1.JitProvisionByEmailRequest{
		Email: "byemail.new@corp.example.com", FirstName: "By", LastName: "Email",
	})
	require.NoError(t, err)
	require.Len(t, pub.accountCreatedUserIDs(t), 1,
		"an existing email must not re-emit account.created")
}
