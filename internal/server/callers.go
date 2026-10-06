// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	log "github.com/Bugs5382/go-log"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/audit"
	"github.com/Steward-GRC/steward-identity/internal/workloadauth"
)

// Caller names, from the service accounts steward-<name>.
const (
	CallerGateway     = "gateway"
	CallerWorkflow    = "workflow"
	CallerObligations = "obligations"
	CallerReporting   = "reporting"
	CallerCollab      = "collab"
	// CallerAdminCLI is identity's own service account: identity-admin runs
	// in the identity pod and sends the pod's token. The admin methods still
	// admit it only with the CLI's client certificate (IDENTITY_ADMIN_CLI_ID).
	CallerAdminCLI = "identity"
)

// gatewayMethods are the methods the gateway calls, each for the signed-in
// user (or, before sign-in, for nobody).
var gatewayMethods = []string{
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
}

// The internal callers act as themselves: each reads what its own job needs
// about a user it names in the request, never by forwarding an actor.
var (
	userReader         = []string{identityv1.IdentityReadService_GetUser_FullMethodName}
	obligationsMethods = []string{
		identityv1.IdentityReadService_GetUser_FullMethodName,
		identityv1.IdentityReadService_ListAllUsers_FullMethodName,
		identityv1.IdentityReadService_ResolveEmail_FullMethodName,
		identityv1.IdentityReadService_ResolveFCMToken_FullMethodName,
	}
	adminCLIMethods = []string{
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
	}
)

// CallerPolicy is identity's per-method allow-list. The gateway passes the
// signed-in user's actor, which the admin services check for site-admin.
// workflow, obligations, reporting and collab act only as themselves, as does
// the admin CLI. A method no caller uses is refused to everyone.
func CallerPolicy() workloadauth.Policy {
	p := workloadauth.Policy{}
	grant := func(caller string, a workloadauth.Access, methods []string) {
		for _, m := range methods {
			if p[m] == nil {
				p[m] = map[string]workloadauth.Access{}
			}
			p[m][caller] = a
		}
	}
	grant(CallerGateway, workloadauth.OnBehalf, gatewayMethods)
	grant(CallerWorkflow, workloadauth.Self, userReader)
	grant(CallerReporting, workloadauth.Self, userReader)
	grant(CallerCollab, workloadauth.Self, userReader)
	grant(CallerObligations, workloadauth.Self, obligationsMethods)
	grant(CallerAdminCLI, workloadauth.Self, adminCLIMethods)
	return p
}

// AuditEmitter records an audit event; the store's EmitAudit in production.
type AuditEmitter interface {
	EmitAudit(ctx context.Context, e audit.Event) error
}

// AuditDenial records a call the workload-auth interceptor refused, as
// rpc.denied. The actor is the authenticated caller (or "unauthenticated"),
// never a user the call claimed.
func AuditDenial(emitter AuditEmitter, lg log.Logger) workloadauth.DenyHook {
	return func(ctx context.Context, d workloadauth.Denial) {
		caller := d.Caller.Name
		if caller == "" {
			caller = "unauthenticated"
		}
		err := emitter.EmitAudit(ctx, audit.Event{
			EventType: "rpc.denied", ActorExternal: "service:" + caller,
			Payload: map[string]any{
				"method": d.Method, "caller": d.Caller.Name, "service_account": d.Caller.ServiceAccount,
				"code": d.Code.String(), "reason": d.Reason,
			},
		})
		if err != nil {
			lg.Ctx(ctx).Error(err, "audit of a refused call failed", log.F("method", d.Method), log.F("caller", caller))
		}
	}
}
