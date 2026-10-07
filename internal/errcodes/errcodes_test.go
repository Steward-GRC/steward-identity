// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package errcodes_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Bugs5382/go-apperr/apperrgrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-identity/internal/errcodes"
)

func TestSSOProviderUnreachableRoundTrip(t *testing.T) {
	st := status.Convert(errcodes.Error(context.Background(),
		errcodes.SSOProviderUnreachable("Example Organisation", errors.New("dial tcp 192.0.2.10:5225: connect: connection refused"))))
	require.Equal(t, codes.Unavailable, st.Code())
	require.Equal(t, "The identity provider is temporarily unavailable. Try again shortly.", st.Message())

	info, ok := apperrgrpc.FromStatus(st)
	require.True(t, ok, "status must carry ErrorInfo")
	require.Equal(t, "SSO_PROVIDER_UNREACHABLE", info.Symbol)
	require.Equal(t, 5001, info.Code)
	require.Equal(t, "identity", info.Domain)
	require.Equal(t, "Example Organisation", info.Metadata["org"])
}

func TestRootRequiredInterpolatesThePermission(t *testing.T) {
	st := status.Convert(errcodes.Error(context.Background(), errcodes.RootRequired("policy.read_sensitive")))
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Equal(t, "Only a root administrator can grant the policy.read_sensitive permission.", st.Message())
}

func TestPendingApprovalsCarriesCountAndPolicies(t *testing.T) {
	st := status.Convert(errcodes.Error(context.Background(), errcodes.UserHasPendingApprovals(2, "Acceptable Use, Backup")))
	require.Equal(t, codes.FailedPrecondition, st.Code())
	require.Contains(t, st.Message(), "2 policy approval(s)")
	require.Contains(t, st.Message(), "(Acceptable Use, Backup)")
	info, _ := apperrgrpc.FromStatus(st)
	require.Equal(t, "USER_HAS_PENDING_APPROVALS", info.Symbol)
	require.Equal(t, "2", info.Metadata["count"])
}

func TestDeleteChecksUnavailableNamesTheStep(t *testing.T) {
	st := status.Convert(errcodes.Error(context.Background(),
		errcodes.UserDeleteChecksUnavailable("approval_check", errors.New("workflow: connection refused"))))
	require.Equal(t, codes.FailedPrecondition, st.Code())
	require.Contains(t, st.Message(), "(approval_check)")
	require.NotContains(t, st.Message(), "connection refused", "the cause never reaches the wire")
	info, _ := apperrgrpc.FromStatus(st)
	require.Equal(t, 5009, info.Code)
	require.Equal(t, "approval_check", info.Metadata["step"])
}

func TestEveryUserSafeCodeKeepsItsGRPCCode(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code codes.Code
		sym  string
	}{
		{errcodes.AdminAuthzRequired(), codes.PermissionDenied, "ADMIN_AUTHZ_REQUIRED"},
		{errcodes.SSOJitDisabled(), codes.PermissionDenied, "SSO_JIT_DISABLED"},
		{errcodes.SessionsUnavailable(errors.New("down")), codes.FailedPrecondition, "SESSIONS_UNAVAILABLE"},
		{errcodes.SessionRevokeUnavailable(errors.New("down")), codes.FailedPrecondition, "SESSION_REVOKE_UNAVAILABLE"},
		{errcodes.LocalAccountsUnavailable(), codes.FailedPrecondition, "LOCAL_ACCOUNTS_UNAVAILABLE"},
		{errcodes.ActAsForbidden(), codes.PermissionDenied, "ACT_AS_FORBIDDEN"},
	} {
		st := status.Convert(errcodes.Error(context.Background(), tc.err))
		require.Equal(t, tc.code, st.Code(), tc.sym)
		info, ok := apperrgrpc.FromStatus(st)
		require.True(t, ok, tc.sym)
		require.Equal(t, tc.sym, info.Symbol)
		require.NotContains(t, st.Message(), "Internal Error", tc.sym+" is user-safe")
	}
}

func TestUncodedErrorsFallBackToInternal(t *testing.T) {
	info, _ := apperrgrpc.FromError(errcodes.Error(context.Background(), errors.New("boom")))
	require.Equal(t, errcodes.CodeInternal, info.Code)
	require.Equal(t, "INTERNAL", info.Symbol)
}

func TestRegistryBandAndDomain(t *testing.T) {
	require.NotEmpty(t, errcodes.Entries())
	for _, e := range errcodes.Entries() {
		require.Equal(t, 5, e.Code/1000, "code %d must be in band 5", e.Code)
		_, ok := errcodes.Registry().Describe(e.Code)
		require.True(t, ok)
	}
}

// docs/error-codes.md is generated from the registry; refresh it with
// UPDATE_DOCS=1 go test ./internal/errcodes.
func TestErrorCodesDocIsCurrent(t *testing.T) {
	const path = "../../docs/error-codes.md"
	want := errcodes.Doc()
	if os.Getenv("UPDATE_DOCS") == "1" {
		require.NoError(t, os.WriteFile(path, []byte(want), 0o600))
	}
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, want, string(got), "docs/error-codes.md is stale: run UPDATE_DOCS=1 go test ./internal/errcodes")
}
