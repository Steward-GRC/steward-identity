// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

func requireActAsForbidden(t *testing.T, err error) {
	t.Helper()
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	info, ok := apperrgrpc.FromError(err)
	require.True(t, ok)
	require.Equal(t, "ACT_AS_FORBIDDEN", info.Symbol)
}

func TestSensitiveActionsAreRefusedDuringActAs(t *testing.T) {
	target, admin := uuid.NewString(), uuid.NewString()
	testRoles.set(target, []string{"site-admin"})
	ctx := actingAsCtx(target, admin)
	h := handlers.NewAdminHandler(nil, testAdminAuth())
	other := uuid.NewString()

	_, err := h.GrantRole(ctx, &identityv1.GrantRoleRequest{UserId: other, Role: "author", Category: "Facilities"})
	requireActAsForbidden(t, err)
	_, err = h.DeleteUser(ctx, &identityv1.DeleteUserRequest{UserId: other})
	requireActAsForbidden(t, err)
	_, err = h.ResetUserPassword(ctx, &identityv1.ResetUserPasswordRequest{UserId: other, NewPassword: "x"})
	requireActAsForbidden(t, err)
	_, err = h.AdminRemoveUserFactor(ctx, &identityv1.AdminRemoveUserFactorRequest{UserId: other, MethodId: "totp"})
	requireActAsForbidden(t, err)
	_, err = handlers.NewReadHandler(nil).RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: target, Kind: "totp"})
	requireActAsForbidden(t, err)
}

func TestAuditCreditsTheRealAdminDuringActAs(t *testing.T) {
	s := newTestStore(t)
	target, admin := uuid.NewString(), uuid.NewString()
	testRoles.set(target, []string{"site-admin"})
	h := handlers.NewAdminHandler(s, testAdminAuth())

	_, err := h.CreateGroup(actingAsCtx(target, admin), &identityv1.CreateGroupRequest{Name: "Finance team"})
	require.NoError(t, err)

	evs, err := s.PendingAuditEvents(context.Background(), 100)
	require.NoError(t, err)
	var found bool
	for _, e := range evs {
		if e.EventType != "group.created" {
			continue
		}
		found = true
		require.NotNil(t, e.ActorUserID)
		require.Equal(t, admin, e.ActorUserID.String(), "the admin at the keyboard is the actor")
		require.Equal(t, target, e.Payload["impersonated_user_id"])
	}
	require.True(t, found, "a group.created event is written")
}
