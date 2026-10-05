// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"

	"github.com/Bugs5382/go-log"
)

// accountCreatedPublisher publishes a raw JSON body on a routing key.
// cmd/server's adapter over a go-rabbitmq Publisher satisfies it; a nil
// publisher disables emission.
type accountCreatedPublisher interface {
	Publish(ctx context.Context, routingKey string, body []byte) error
}

// routingKeyAccountCreated is the AMQP routing key identity publishes on the
// "jobs" exchange whenever a brand-new user account is created by ANY route:
// /setup bootstrap, an admin local-account create, or a SAML/JIT federated first
// login. the obligations service binds its welcome queue on this key and sends the
// welcome-account email exactly once per account. Making it a single
// account-created signal (rather than one email per code path) is what
// guarantees every creation route is covered.
const routingKeyAccountCreated = "account.created"

// accountCreatedEvent is the wire payload: the event name plus the platform
// user id of the freshly-created account. the obligations service resolves the
// recipient's name+email from identity by this id (exactly like the welcome
// resend RPC), so the event stays minimal and carries no PII on the wire. Its
// JSON shape matches modules/the obligations service/internal/consumer.accountCreatedEvent.
type accountCreatedEvent struct {
	EventType string `json:"event_type"`
	UserID    string `json:"user_id"`
}

// emitAccountCreated publishes one account.created event for userID. It is
// best-effort and nil-safe: a nil publisher, an empty userID, or a publish
// failure is logged and swallowed, never returned, so a lost event never fails
// the (already-committed) account creation. the obligations service's welcome send is
// deduped once-per-account, and an admin can always resend a missed welcome via
// the WelcomeService RPC, so at-least-once with an occasional drop is safe here.
func emitAccountCreated(ctx context.Context, pub accountCreatedPublisher, userID string) {
	if pub == nil || userID == "" {
		return
	}
	body, err := json.Marshal(accountCreatedEvent{EventType: routingKeyAccountCreated, UserID: userID})
	if err != nil {
		return
	}
	if err := pub.Publish(ctx, routingKeyAccountCreated, body); err != nil {
		l := log.Ctx(ctx)
		l.Warn().Err(err).Str("user_id", userID).Msg("account-created: emit")
	}
}
