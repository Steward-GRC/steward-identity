// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"testing"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// TestAuthorizeUnauthorizedCarriesAdminAuthzCode proves the central admin
// authz gate returns a coded ErrorInfo the gateway can relay: an
// unauthenticated caller gets a PermissionDenied status carrying
// ErrorInfo{Reason: ADMIN_AUTHZ_REQUIRED, codeNum: 5002, Domain: identity} and
// the user-safe registry message. No DB needed, so this always runs.
func TestAuthorizeUnauthorizedCarriesAdminAuthzCode(t *testing.T) {
	_, err := ssoAdminAuth().Authorize(noopCtx())
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status")
	require.Equal(t, codes.PermissionDenied, st.Code())

	info, ok := apperrgrpc.FromStatus(st)
	require.True(t, ok, "status must carry ErrorInfo")
	require.Equal(t, "ADMIN_AUTHZ_REQUIRED", info.Symbol)
	require.Equal(t, 5002, info.Code)
	require.Equal(t, "identity", info.Domain)
	require.Equal(t, registryMessage(t, errcodes.CodeAdminAuthzRequired), st.Message())
}

// registryMessage is the user-safe message the registry holds for code.
func registryMessage(t *testing.T, code int) string {
	t.Helper()
	e, ok := errcodes.Registry().Describe(code)
	require.True(t, ok, "code %d is registered", code)
	return e.Message
}

// When backend provisioning fails during org creation, AddOrganization
// returns Unavailable carrying SSO_PROVIDER_UNREACHABLE (5001) with the
// organisation's name in the metadata and the user-safe message.
func TestAddOrganizationSSOProviderUnreachableCarriesCode(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	f.failCreate = true
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth())

	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName:  "Partner Organisation",
		Domain:   "partner.example.net",
		Protocol: "oidc",
		Config:   map[string]string{"issuer": "https://idp.partner.example.net", "clientId": "steward"},
	})
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status")
	require.Equal(t, codes.Unavailable, st.Code())

	info, ok := apperrgrpc.FromStatus(st)
	require.True(t, ok, "status must carry ErrorInfo")
	require.Equal(t, "SSO_PROVIDER_UNREACHABLE", info.Symbol)
	require.Equal(t, 5001, info.Code)
	require.Equal(t, "identity", info.Domain)
	require.Equal(t, "Partner Organisation", info.Metadata["org"], "metadata must carry the resolved org name, not a raw id")
	require.Equal(t, registryMessage(t, errcodes.CodeSSOProviderUnreachable), st.Message())
}

// Without the Kratos admin API the local-account RPCs decline with a coded
// precondition and the user-safe message. No DB needed: the guard declines
// before the store is touched.
func TestLocalAccountRPCsCarryLocalAccountsUnavailableCode(t *testing.T) {
	h := handlers.NewAdminHandler(nil, ssoAdminAuth())
	ctx := adminCtx(uuid.NewString())
	calls := map[string]func() error{
		"CreateLocalUser": func() error {
			_, err := h.CreateLocalUser(ctx, &identityv1.CreateLocalUserRequest{Username: "u", Email: "u@example.org", Name: "U", Password: "p"})
			return err
		},
		"ResetUserPassword": func() error {
			_, err := h.ResetUserPassword(ctx, &identityv1.ResetUserPasswordRequest{UserId: uuid.NewString(), NewPassword: "p"})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, "error must be a gRPC status")
			require.Equal(t, codes.FailedPrecondition, st.Code())
			info, ok := apperrgrpc.FromStatus(st)
			require.True(t, ok, "status must carry ErrorInfo")
			require.Equal(t, "LOCAL_ACCOUNTS_UNAVAILABLE", info.Symbol)
			require.Equal(t, 5007, info.Code)
			require.Equal(t, "identity", info.Domain)
			require.Equal(t, registryMessage(t, errcodes.CodeLocalAccountsUnavailable), st.Message())
		})
	}
}
