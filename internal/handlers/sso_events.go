// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"

	"github.com/Bugs5382/go-log"
)

// routingKeySSOLifecycle is the single AMQP routing key every SSO lifecycle
// event now shares. The concrete event (sso.account_provisioned,
// sso.activated, user.break_glass.login, …) is carried in the payload's
// "event" field rather than the routing key, so a single consumer binding
// (obligations) receives the whole lifecycle stream and keys
// its templates off the event name.
const routingKeySSOLifecycle = "sso.lifecycle"

// Event names carried in the lifecycle envelope's "event" field. The values
// are stable wire contract — the obligations service's Task-31 templates key off
// them — so they must never change even though the routing key no longer
// does.
const (
	eventSSOAccountProvisioned = "sso.account_provisioned"
	eventSSOAccessGranted      = "sso.access_granted"
	eventUserBreakGlassLogin   = "user.break_glass.login"
)

// rawPublisher is the publisher seam: it publishes a raw JSON body on a routing
// key ("jobs" exchange). cmd/server's adapter over a go-rabbitmq Publisher
// satisfies it. SSOEventEmitter wraps one to turn typed lifecycle events into
// that raw form.
type rawPublisher interface {
	Publish(ctx context.Context, routingKey string, body []byte) error
}

// ssoEventPublisher is the seam the handlers emit through. PublishSSO takes an
// event name + a free-form vars bag (the fields a downstream email template
// needs) and is responsible for shaping the wire envelope. A nil publisher
// (the seam is optional) disables emission; SSOEventEmitter's PublishSSO is
// itself nil-safe on both the emitter and its wrapped publisher.
type ssoEventPublisher interface {
	PublishSSO(ctx context.Context, event string, vars map[string]any) error
}

// ssoLifecycleEnvelope is the wire shape published on routingKeySSOLifecycle:
// the event name plus the template variables. Kept intentionally small and
// stable — Task-31 templates unmarshal exactly this.
type ssoLifecycleEnvelope struct {
	Event string         `json:"event"`
	Vars  map[string]any `json:"vars"`
}

// SSOEventEmitter adapts a raw mq.Publisher to the ssoEventPublisher seam by
// marshalling {event, vars} JSON and publishing it on the shared
// "sso.lifecycle" routing key. Nil-safe: a nil emitter or a nil wrapped
// publisher makes PublishSSO a no-op.
type SSOEventEmitter struct {
	pub rawPublisher
}

// NewSSOEventEmitter wraps a raw publisher (the "jobs"-exchange mq.Publisher)
// as an ssoEventPublisher. Passing a nil publisher yields an emitter whose
// PublishSSO is a no-op, so callers never need to nil-check the publisher.
func NewSSOEventEmitter(pub rawPublisher) *SSOEventEmitter {
	return &SSOEventEmitter{pub: pub}
}

// PublishSSO marshals the {event, vars} envelope and publishes it on
// routingKeySSOLifecycle. A marshal error is returned; a nil emitter/publisher
// is a silent no-op.
func (e *SSOEventEmitter) PublishSSO(ctx context.Context, event string, vars map[string]any) error {
	if e == nil || e.pub == nil {
		return nil
	}
	body, err := json.Marshal(ssoLifecycleEnvelope{Event: event, Vars: vars})
	if err != nil {
		return err
	}
	return e.pub.Publish(ctx, routingKeySSOLifecycle, body)
}

// emitSSOEvent is the shared best-effort emit path used by every SSO lifecycle
// emitter (admin mutations + JIT welcome). A nil publisher skips emission; a
// publish failure is logged and swallowed — a lost lifecycle event must never
// fail the (already-committed) action that produced it.
func emitSSOEvent(ctx context.Context, pub ssoEventPublisher, event string, vars map[string]any) {
	if pub == nil {
		return
	}
	if err := pub.PublishSSO(ctx, event, vars); err != nil {
		lg := log.Ctx(ctx)
		lg.Warn().Err(err).Str("event", event).Msg("sso: lifecycle event emit")
	}
}
