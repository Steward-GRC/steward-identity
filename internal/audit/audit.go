// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit turns identity's audit events into steward-audit's contract:
// a steward.audit.v1.AuditEvent, as protobuf binary, in a go-outbox message
// the relay publishes to the "audit" topic exchange with routing key
// audit.<tier>.
package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	outbox "github.com/Bugs5382/go-outbox"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/audit/v1"
)

// ContentType is the AMQP content type every event is published with.
const ContentType = "application/protobuf; proto=steward.audit.v1.AuditEvent"

// Event is one audit event as the store records it. ActorUserID is set for
// a platform user, ActorExternal for anyone else (the admin CLI's operator,
// a system job).
type Event struct {
	ID            int64
	EventType     string
	ActorUserID   *uuid.UUID
	ActorExternal string
	TargetUserID  *uuid.UUID
	TargetGroupID *uuid.UUID
	Payload       map[string]any
	// Left zero, it is stamped when the event is encoded.
	CreatedAt time.Time
}

var errNoType = errors.New("audit: event has no type")

// tier is the retention class: sign-ins and session events are activity,
// everything else is audit.
func tier(eventType string) auditv1.Tier {
	switch eventType {
	case "user.login.success", "session.login", "session.revoked":
		return auditv1.Tier_TIER_ACTIVITY
	default:
		return auditv1.Tier_TIER_AUDIT
	}
}

// Encode builds the outbox message for ev. During act-as the event is
// credited to the real admin, and the actor it was recorded with (the
// target) is kept in the impersonated_user_id attribute.
func Encode(ctx context.Context, ev Event) (outbox.Message, error) {
	if ev.EventType == "" {
		return outbox.Message{}, errNoType
	}
	attrs := make(map[string]string, len(ev.Payload)+1)
	for k, v := range ev.Payload {
		attrs[k] = stringify(v)
	}
	actor := ev.ActorExternal
	if ev.ActorUserID != nil {
		actor = ev.ActorUserID.String()
	}
	if a, ok := grpcactor.FromContext(ctx); ok && a.Impersonated() {
		if actor != "" {
			attrs["impersonated_user_id"] = actor
		}
		actor = a.Impersonator
	}
	subject, group := "", ""
	switch {
	case ev.TargetUserID != nil:
		subject = "user:" + ev.TargetUserID.String()
	case ev.TargetGroupID != nil:
		subject = "group:" + ev.TargetGroupID.String()
	}
	if ev.TargetGroupID != nil {
		group = ev.TargetGroupID.String()
	}
	at := ev.CreatedAt
	if at.IsZero() {
		at = time.Now()
	}
	t := tier(ev.EventType)
	body, err := proto.Marshal(&auditv1.AuditEvent{
		Tier: t, Action: ev.EventType, ActorUserId: actor, Subject: subject, GroupId: group,
		OccurredAt: timestamppb.New(at.UTC()), Attributes: attrs,
	})
	if err != nil {
		return outbox.Message{}, fmt.Errorf("audit: encode event: %w", err)
	}
	return outbox.Message{Topic: "audit." + tierName(t), Payload: body, ContentType: ContentType}, nil
}

func tierName(t auditv1.Tier) string {
	if t == auditv1.Tier_TIER_ACTIVITY {
		return "activity"
	}
	return "audit"
}

// Decode reads an encoded payload back into an Event. Attribute values come
// back as strings.
func Decode(body []byte) (Event, error) {
	var pe auditv1.AuditEvent
	if err := proto.Unmarshal(body, &pe); err != nil {
		return Event{}, fmt.Errorf("audit: decode event: %w", err)
	}
	ev := Event{EventType: pe.GetAction(), CreatedAt: pe.GetOccurredAt().AsTime(), Payload: map[string]any{}}
	for k, v := range pe.GetAttributes() {
		ev.Payload[k] = v
	}
	if id, err := uuid.Parse(pe.GetActorUserId()); err == nil {
		ev.ActorUserID = &id
	} else {
		ev.ActorExternal = pe.GetActorUserId()
	}
	if rest, ok := strings.CutPrefix(pe.GetSubject(), "user:"); ok {
		if id, err := uuid.Parse(rest); err == nil {
			ev.TargetUserID = &id
		}
	}
	if id, err := uuid.Parse(pe.GetGroupId()); err == nil {
		ev.TargetGroupID = &id
	}
	return ev, nil
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
