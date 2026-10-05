// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// recordingAcctPub captures every account.created publish so the wire shape and
// emission count can be asserted without a broker or a database.
type recordingAcctPub struct {
	calls []struct {
		routingKey string
		body       []byte
	}
	err error
}

func (p *recordingAcctPub) Publish(_ context.Context, routingKey string, body []byte) error {
	p.calls = append(p.calls, struct {
		routingKey string
		body       []byte
	}{routingKey, append([]byte(nil), body...)})
	return p.err
}

// TestEmitAccountCreated_WireShape asserts emitAccountCreated marshals
// {event_type, user_id} onto the "account.created" routing key — the exact
// envelope the obligations service's account-created consumer unmarshals. Pure unit
// test (no DB), so it runs everywhere.
func TestEmitAccountCreated_WireShape(t *testing.T) {
	pub := &recordingAcctPub{}
	emitAccountCreated(context.Background(), pub, "user-123")

	require.Len(t, pub.calls, 1)
	require.Equal(t, "account.created", pub.calls[0].routingKey)

	var evt accountCreatedEvent
	require.NoError(t, json.Unmarshal(pub.calls[0].body, &evt))
	require.Equal(t, "account.created", evt.EventType)
	require.Equal(t, "user-123", evt.UserID)
}

// TestEmitAccountCreated_NilSafeAndGuards proves the emit is a no-op for a nil
// publisher or an empty user id, and that a publish error is swallowed (never
// panics / never fails the caller).
func TestEmitAccountCreated_NilSafeAndGuards(t *testing.T) {
	// nil publisher: no panic, nothing to assert beyond "does not blow up".
	emitAccountCreated(context.Background(), nil, "user-1")

	// empty user id: skipped even with a live publisher.
	pub := &recordingAcctPub{}
	emitAccountCreated(context.Background(), pub, "")
	require.Empty(t, pub.calls)

	// publish error is swallowed.
	failing := &recordingAcctPub{err: errors.New("broker down")}
	emitAccountCreated(context.Background(), failing, "user-2")
	require.Len(t, failing.calls, 1)
}
