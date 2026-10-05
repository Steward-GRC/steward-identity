// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"

	"github.com/Bugs5382/go-log"
)

// membershipPublisher publishes a raw JSON body on a routing key.
// cmd/server's adapter over a go-rabbitmq Publisher satisfies it; a nil
// publisher disables emission.
type membershipPublisher interface {
	Publish(ctx context.Context, routingKey string, body []byte) error
}

// routingKeyMembershipChanged is the AMQP routing key identity uses to publish
// membership-change events on the "jobs" exchange. the obligations service binds its
// membership reconcile queue on this same key.
const routingKeyMembershipChanged = "membership.changed"

// membershipChangedEvent is the wire payload. Its JSON shape (event_type +
// user_id) matches the obligations service's membership consumer.
type membershipChangedEvent struct {
	EventType string `json:"event_type"`
	UserID    string `json:"user_id"`
}

// WithMembershipPublisher wires the "jobs"-exchange publisher so membership
// mutations emit membership.changed events. Nil skips emission; returns the
// handler for chaining.
func (h *AdminHandler) WithMembershipPublisher(p membershipPublisher) *AdminHandler {
	h.membershipPub = p
	return h
}

// emitMembershipChanged publishes one membership.changed event for userID.
// Best-effort: a nil publisher or a publish failure is logged, never returned,
// so a lost event never fails the mutation (the obligations service's reconcile is
// idempotent and re-triggers on the next change; completion counts already
// ignore orphaned acks).
func (h *AdminHandler) emitMembershipChanged(ctx context.Context, userID string) {
	if h.membershipPub == nil {
		return
	}
	body, err := json.Marshal(membershipChangedEvent{EventType: routingKeyMembershipChanged, UserID: userID})
	if err != nil {
		return
	}
	if err := h.membershipPub.Publish(ctx, routingKeyMembershipChanged, body); err != nil {
		l := logger.Ctx(ctx)
		l.Warn("membership-changed: emit", log.F("user_id", userID), log.F("error", errText(err)))
	}
}
