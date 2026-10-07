// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

	log "github.com/Bugs5382/go-log"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/audit"
	"github.com/Steward-GRC/steward-identity/internal/workloadauth"
)

var identityServices = []grpc.ServiceDesc{
	identityv1.IdentityReadService_ServiceDesc, identityv1.IdentityAdminService_ServiceDesc, identityv1.IdentitySSOAdminService_ServiceDesc,
}

func allMethods() []string {
	var out []string
	for _, sd := range identityServices {
		for _, md := range sd.Methods {
			out = append(out, "/"+sd.ServiceName+"/"+md.MethodName)
		}
	}
	return out
}

// requireCallerMethods checks caller is listed with access on exactly want.
func requireCallerMethods(t *testing.T, caller string, want map[string]workloadauth.Access) {
	t.Helper()
	p := CallerPolicy()
	got := map[string]workloadauth.Access{}
	for _, m := range allMethods() {
		if a, ok := p.Lookup(m, caller); ok {
			got[m] = a
		}
	}
	require.Equal(t, want, got)
}

func self(methods ...string) map[string]workloadauth.Access {
	out := map[string]workloadauth.Access{}
	for _, m := range methods {
		out[m] = workloadauth.Self
	}
	return out
}

func TestCallerPolicyListsOnlyMethodsIdentityServes(t *testing.T) {
	methods := map[string]bool{}
	for _, m := range allMethods() {
		methods[m] = true
	}
	for m, callers := range CallerPolicy() {
		require.True(t, methods[m], "the policy lists %s, which identity doesn't serve", m)
		require.NotEmpty(t, callers, "%s is listed with no caller", m)
	}
}

func TestCallerPolicyGatewayActsForTheSignedInUser(t *testing.T) {
	// The methods steward-gateway calls, written out so that dropping or
	// adding one in callers.go fails here.
	want := map[string]workloadauth.Access{}
	for _, m := range []string{
		identityv1.IdentityReadService_BootstrapRoot_FullMethodName,
		identityv1.IdentityReadService_CheckBreakGlassEligibility_FullMethodName,
		identityv1.IdentityReadService_Discover_FullMethodName,
		identityv1.IdentityReadService_EnrollTotpBegin_FullMethodName,
		identityv1.IdentityReadService_EnrollTotpConfirm_FullMethodName,
		identityv1.IdentityReadService_GetAuthConfig_FullMethodName,
		identityv1.IdentityReadService_GetGroup_FullMethodName,
		identityv1.IdentityReadService_GetSetupState_FullMethodName,
		identityv1.IdentityReadService_GetUser_FullMethodName,
		identityv1.IdentityReadService_GetUserByEmail_FullMethodName,
		identityv1.IdentityReadService_JitProvisionByEmail_FullMethodName,
		identityv1.IdentityReadService_ListAllUsers_FullMethodName,
		identityv1.IdentityReadService_ListUserFactors_FullMethodName,
		identityv1.IdentityReadService_ListUserIdpGroups_FullMethodName,
		identityv1.IdentityReadService_ListUsersByEmail_FullMethodName,
		identityv1.IdentityReadService_ListUsersInGroup_FullMethodName,
		identityv1.IdentityReadService_ListWebauthnCredentials_FullMethodName,
		identityv1.IdentityReadService_MarkEmailVerified_FullMethodName,
		identityv1.IdentityReadService_RemoveFactor_FullMethodName,
		identityv1.IdentityReadService_RemoveWebauthnCredential_FullMethodName,
		identityv1.IdentityReadService_RenameMFAMethod_FullMethodName,
		identityv1.IdentityReadService_RequestLoginOtp_FullMethodName,
		identityv1.IdentityReadService_RequestPasswordReset_FullMethodName,
		identityv1.IdentityReadService_ResetPasswordWithCode_FullMethodName,
		identityv1.IdentityReadService_RevokeMySessions_FullMethodName,
		identityv1.IdentityReadService_SendEmailOtp_FullMethodName,
		identityv1.IdentityReadService_VerifyEmailOtp_FullMethodName,
		identityv1.IdentityReadService_VerifyLoginOtp_FullMethodName,
		identityv1.IdentityReadService_VerifyTotp_FullMethodName,
		identityv1.IdentityReadService_WebauthnAssertBegin_FullMethodName,
		identityv1.IdentityReadService_WebauthnAssertFinish_FullMethodName,
		identityv1.IdentityReadService_WebauthnRegisterBegin_FullMethodName,
		identityv1.IdentityReadService_WebauthnRegisterFinish_FullMethodName,
		identityv1.IdentityAdminService_ActiveBreakGlass_FullMethodName,
		identityv1.IdentityAdminService_AddUserToGroup_FullMethodName,
		identityv1.IdentityAdminService_AdminListUserFactors_FullMethodName,
		identityv1.IdentityAdminService_AdminRemoveUserFactor_FullMethodName,
		identityv1.IdentityAdminService_AdminRenameUserFactor_FullMethodName,
		identityv1.IdentityAdminService_BreakGlassReveal_FullMethodName,
		identityv1.IdentityAdminService_CompleteOnboarding_FullMethodName,
		identityv1.IdentityAdminService_CreateLocalUser_FullMethodName,
		identityv1.IdentityAdminService_DeleteUser_FullMethodName,
		identityv1.IdentityAdminService_DisableUser_FullMethodName,
		identityv1.IdentityAdminService_EnableUser_FullMethodName,
		identityv1.IdentityAdminService_GrantGroupManager_FullMethodName,
		identityv1.IdentityAdminService_GrantRole_FullMethodName,
		identityv1.IdentityAdminService_ListUserSessions_FullMethodName,
		identityv1.IdentityAdminService_MergeAccounts_FullMethodName,
		identityv1.IdentityAdminService_PreviewAccountMerge_FullMethodName,
		identityv1.IdentityAdminService_PreviewUserDeletion_FullMethodName,
		identityv1.IdentityAdminService_RemoveUserFromGroup_FullMethodName,
		identityv1.IdentityAdminService_RequestStepUpOtp_FullMethodName,
		identityv1.IdentityAdminService_ResetUserPassword_FullMethodName,
		identityv1.IdentityAdminService_RevokeGroupManager_FullMethodName,
		identityv1.IdentityAdminService_RevokeRole_FullMethodName,
		identityv1.IdentityAdminService_RevokeUserSessions_FullMethodName,
		identityv1.IdentityAdminService_SetUserPolicyOverride_FullMethodName,
		identityv1.IdentityAdminService_TransferRoot_FullMethodName,
		identityv1.IdentityAdminService_UpdateMyProfile_FullMethodName,
		identityv1.IdentityAdminService_UpdateUserProfile_FullMethodName,
		identityv1.IdentitySSOAdminService_ActivateOrganization_FullMethodName,
		identityv1.IdentitySSOAdminService_AddGroupMapping_FullMethodName,
		identityv1.IdentitySSOAdminService_AddOrganization_FullMethodName,
		identityv1.IdentitySSOAdminService_ChangeOrgProtocol_FullMethodName,
		identityv1.IdentitySSOAdminService_DeleteGroupMapping_FullMethodName,
		identityv1.IdentitySSOAdminService_DeleteOrganization_FullMethodName,
		identityv1.IdentitySSOAdminService_DisableOrganization_FullMethodName,
		identityv1.IdentitySSOAdminService_ForceRotateSPCertificate_FullMethodName,
		identityv1.IdentitySSOAdminService_GetOrganization_FullMethodName,
		identityv1.IdentitySSOAdminService_GetSPCertificate_FullMethodName,
		identityv1.IdentitySSOAdminService_ListGroupMappings_FullMethodName,
		identityv1.IdentitySSOAdminService_ListOrganizations_FullMethodName,
		identityv1.IdentitySSOAdminService_ListSPCertificates_FullMethodName,
		identityv1.IdentitySSOAdminService_RecordBreakGlassLogin_FullMethodName,
		identityv1.IdentitySSOAdminService_RecordIdPTestResult_FullMethodName,
		identityv1.IdentitySSOAdminService_StartDomainVerification_FullMethodName,
		identityv1.IdentitySSOAdminService_UpdateIdPConnection_FullMethodName,
		identityv1.IdentitySSOAdminService_VerifyDomain_FullMethodName,
	} {
		want[m] = workloadauth.OnBehalf
	}
	requireCallerMethods(t, CallerGateway, want)
	for _, m := range []string{
		identityv1.IdentityReadService_ResolveEmail_FullMethodName,
		identityv1.IdentityReadService_ResolveFCMToken_FullMethodName,
		identityv1.IdentityAdminService_BootstrapInitialAdmin_FullMethodName,
	} {
		_, ok := CallerPolicy().Lookup(m, CallerGateway)
		require.False(t, ok, "%s is never reached through the gateway", m)
	}
}

func TestCallerPolicyInternalCallersActAsThemselves(t *testing.T) {
	requireCallerMethods(t, CallerWorkflow, self(identityv1.IdentityReadService_GetUser_FullMethodName))
	requireCallerMethods(t, CallerReporting, self(identityv1.IdentityReadService_GetUser_FullMethodName))
	requireCallerMethods(t, CallerCollab, self(identityv1.IdentityReadService_GetUser_FullMethodName))
	requireCallerMethods(t, CallerObligations, self(
		identityv1.IdentityReadService_GetUser_FullMethodName,
		identityv1.IdentityReadService_ListAllUsers_FullMethodName,
		identityv1.IdentityReadService_ResolveEmail_FullMethodName,
		identityv1.IdentityReadService_ResolveFCMToken_FullMethodName,
	))
}

func TestCallerPolicyAdminCLIRunsInTheIdentityPod(t *testing.T) {
	requireCallerMethods(t, CallerAdminCLI, self(
		identityv1.IdentityReadService_GetUser_FullMethodName,
		identityv1.IdentityReadService_ListUsersByEmail_FullMethodName,
		identityv1.IdentityReadService_GetGroup_FullMethodName,
		identityv1.IdentityReadService_ListGroups_FullMethodName,
		identityv1.IdentityAdminService_EnableUser_FullMethodName,
		identityv1.IdentityAdminService_DisableUser_FullMethodName,
		identityv1.IdentityAdminService_GrantRole_FullMethodName,
		identityv1.IdentityAdminService_RevokeRole_FullMethodName,
		identityv1.IdentityAdminService_CreateGroup_FullMethodName,
		identityv1.IdentityAdminService_RenameGroup_FullMethodName,
		identityv1.IdentityAdminService_DeleteGroup_FullMethodName,
		identityv1.IdentityAdminService_AddUserToGroup_FullMethodName,
		identityv1.IdentityAdminService_RemoveUserFromGroup_FullMethodName,
		identityv1.IdentityAdminService_SetGroupParent_FullMethodName,
		identityv1.IdentityAdminService_BootstrapInitialAdmin_FullMethodName,
	))
}

func TestCallerPolicyListsNoOtherCaller(t *testing.T) {
	known := map[string]bool{CallerGateway: true, CallerWorkflow: true, CallerObligations: true, CallerReporting: true, CallerCollab: true, CallerAdminCLI: true}
	for m, callers := range CallerPolicy() {
		for c := range callers {
			require.True(t, known[c], "%s lists unknown caller %q", m, c)
		}
	}
	for _, c := range []string{"core", "delivery", "ai", "audit"} {
		requireCallerMethods(t, c, map[string]workloadauth.Access{})
	}
}

type recordingEmitter struct{ evs []audit.Event }

func (r *recordingEmitter) EmitAudit(_ context.Context, ev audit.Event) error {
	r.evs = append(r.evs, ev)
	return nil
}

func TestAuditDenialRecordsTheCallerNotAClaimedUser(t *testing.T) {
	rec := &recordingEmitter{}
	hook := AuditDenial(rec, log.Nop())
	hook(context.Background(), workloadauth.Denial{
		Method: identityv1.IdentityAdminService_GrantRole_FullMethodName, Code: codes.PermissionDenied, Reason: workloadauth.ReasonMethodNotAllowed,
		Caller: workloadauth.Caller{Name: "reporting", ServiceAccount: "steward/steward-reporting"},
	})
	hook(context.Background(), workloadauth.Denial{Method: "/m", Code: codes.Unauthenticated, Reason: workloadauth.ReasonNoToken})
	require.Len(t, rec.evs, 2)
	require.Equal(t, "rpc.denied", rec.evs[0].EventType)
	require.Nil(t, rec.evs[0].ActorUserID, "a refused call is never credited to a user")
	require.Equal(t, "service:reporting", rec.evs[0].ActorExternal)
	require.Equal(t, map[string]any{
		"method": identityv1.IdentityAdminService_GrantRole_FullMethodName, "caller": "reporting", "service_account": "steward/steward-reporting",
		"code": "PermissionDenied", "reason": workloadauth.ReasonMethodNotAllowed,
	}, rec.evs[0].Payload)
	require.Equal(t, "service:unauthenticated", rec.evs[1].ActorExternal)
}
