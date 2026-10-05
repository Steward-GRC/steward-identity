// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package audit_test

import (
	"context"
	"testing"
	"time"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	auditv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/audit/v1"
	"github.com/Steward-GRC/steward-identity/internal/audit"
)

func decodeProto(t *testing.T, b []byte) *auditv1.AuditEvent {
	t.Helper()
	var pe auditv1.AuditEvent
	require.NoError(t, proto.Unmarshal(b, &pe))
	return &pe
}

func TestEncodeMapsEveryField(t *testing.T) {
	actor, target, group := uuid.New(), uuid.New(), uuid.New()
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name      string
		in        audit.Event
		wantTopic string
		wantTier  auditv1.Tier
		wantActor string
		wantSubj  string
		wantGroup string
	}{
		{"external actor, user target", audit.Event{EventType: "user.bootstrap_root", ActorExternal: "bootstrap",
			TargetUserID: &target, Payload: map[string]any{"bootstrap": true}, CreatedAt: at},
			"audit.audit", auditv1.Tier_TIER_AUDIT, "bootstrap", "user:" + target.String(), ""},
		{"platform actor", audit.Event{EventType: "role.granted", ActorUserID: &actor, TargetUserID: &target, CreatedAt: at},
			"audit.audit", auditv1.Tier_TIER_AUDIT, actor.String(), "user:" + target.String(), ""},
		{"sign-in is activity", audit.Event{EventType: "user.login.success", ActorUserID: &actor, TargetUserID: &actor, CreatedAt: at},
			"audit.activity", auditv1.Tier_TIER_ACTIVITY, actor.String(), "user:" + actor.String(), ""},
		{"group target", audit.Event{EventType: "group.created", ActorUserID: &actor, TargetGroupID: &group, CreatedAt: at},
			"audit.audit", auditv1.Tier_TIER_AUDIT, actor.String(), "group:" + group.String(), group.String()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := audit.Encode(context.Background(), tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.wantTopic, msg.Topic)
			require.Equal(t, audit.ContentType, msg.ContentType)
			pe := decodeProto(t, msg.Payload)
			require.Equal(t, tc.wantTier, pe.GetTier())
			require.Equal(t, tc.in.EventType, pe.GetAction())
			require.Equal(t, tc.wantActor, pe.GetActorUserId())
			require.Equal(t, tc.wantSubj, pe.GetSubject())
			require.Equal(t, tc.wantGroup, pe.GetGroupId())
			require.True(t, pe.GetOccurredAt().AsTime().Equal(at))
		})
	}
}

func TestEncodeStringifiesAttributes(t *testing.T) {
	msg, err := audit.Encode(context.Background(), audit.Event{EventType: "x.y",
		Payload: map[string]any{"s": "v", "n": 3, "b": true, "nil": nil}})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"s": "v", "n": "3", "b": "true", "nil": ""}, decodeProto(t, msg.Payload).GetAttributes())
}

func TestEncodeStampsAMissingTime(t *testing.T) {
	before := time.Now().Add(-time.Second)
	msg, err := audit.Encode(context.Background(), audit.Event{EventType: "x.y"})
	require.NoError(t, err)
	require.True(t, decodeProto(t, msg.Payload).GetOccurredAt().AsTime().After(before))
}

func TestEncodeRefusesAnEventWithoutAType(t *testing.T) {
	_, err := audit.Encode(context.Background(), audit.Event{})
	require.Error(t, err)
}

func TestEncodeCreditsTheRealAdminDuringActAs(t *testing.T) {
	admin, target, grantee := uuid.New(), uuid.New(), uuid.New()
	ctx := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: target.String(), Impersonator: admin.String()})
	msg, err := audit.Encode(ctx, audit.Event{EventType: "role.granted", ActorUserID: &target, TargetUserID: &grantee})
	require.NoError(t, err)
	pe := decodeProto(t, msg.Payload)
	require.Equal(t, admin.String(), pe.GetActorUserId())
	require.Equal(t, target.String(), pe.GetAttributes()["impersonated_user_id"])

	plain := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: target.String()})
	msg, err = audit.Encode(plain, audit.Event{EventType: "role.granted", ActorUserID: &target, TargetUserID: &grantee})
	require.NoError(t, err)
	pe = decodeProto(t, msg.Payload)
	require.Equal(t, target.String(), pe.GetActorUserId())
	_, has := pe.GetAttributes()["impersonated_user_id"]
	require.False(t, has)
}

func TestEncodeDuringActAsKeepsAnExternalActor(t *testing.T) {
	admin := uuid.New()
	ctx := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: "someone", Impersonator: admin.String()})
	msg, err := audit.Encode(ctx, audit.Event{EventType: "x.y", ActorExternal: "cli:alice"})
	require.NoError(t, err)
	pe := decodeProto(t, msg.Payload)
	require.Equal(t, admin.String(), pe.GetActorUserId())
	require.Equal(t, "cli:alice", pe.GetAttributes()["impersonated_user_id"])
}

func TestDecodeReadsAnEncodedEventBack(t *testing.T) {
	actor, target, group := uuid.New(), uuid.New(), uuid.New()
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, in := range []audit.Event{
		{EventType: "role.granted", ActorUserID: &actor, TargetUserID: &target, Payload: map[string]any{"role": "author"}, CreatedAt: at},
		{EventType: "group.created", ActorExternal: "cli:alice", TargetGroupID: &group, Payload: map[string]any{}, CreatedAt: at},
	} {
		msg, err := audit.Encode(context.Background(), in)
		require.NoError(t, err)
		got, err := audit.Decode(msg.Payload)
		require.NoError(t, err)
		require.Equal(t, in.EventType, got.EventType)
		require.Equal(t, in.ActorUserID, got.ActorUserID)
		require.Equal(t, in.ActorExternal, got.ActorExternal)
		require.Equal(t, in.TargetUserID, got.TargetUserID)
		require.Equal(t, in.TargetGroupID, got.TargetGroupID)
		require.True(t, got.CreatedAt.Equal(at))
		for k, v := range in.Payload {
			require.Equal(t, v, got.Payload[k])
		}
	}
}
