// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package errcodes holds the identity service's coded errors (band 5) and
// turns them into gRPC statuses through go-apperr.
package errcodes

import (
	"context"
	"errors"
	"strconv"
	"sync"

	apperr "github.com/Bugs5382/go-apperr"
	"github.com/Bugs5382/go-apperr/apperrgrpc"
	log "github.com/Bugs5382/go-log"
)

// Domain is the ErrorInfo domain every identity error carries.
const Domain = "identity"

// The identity service's codes.
const (
	CodeInternal                    = 5000
	CodeSSOProviderUnreachable      = 5001
	CodeAdminAuthzRequired          = 5002
	CodeRootRequired                = 5003
	CodeSSOJitDisabled              = 5004
	CodeSessionsUnavailable         = 5005
	CodeSessionRevokeUnavailable    = 5006
	CodeLocalAccountsUnavailable    = 5007
	CodeUserHasPendingApprovals     = 5008
	CodeUserDeleteChecksUnavailable = 5009
)

// Entries returns the registry entries.
func Entries() []apperr.Entry {
	return []apperr.Entry{
		{Code: CodeInternal, Symbol: "INTERNAL", Category: apperr.CategoryInternal,
			Title: "identity", Cause: "an uncoded failure inside the identity service"},
		{Code: CodeSSOProviderUnreachable, Symbol: "SSO_PROVIDER_UNREACHABLE", Category: apperr.CategoryUnavailable,
			Title: "SSO connection", Cause: "the SSO broker's admin API refused or didn't answer while a connection was set up; the org metadata names the organisation",
			UserSafe: true, Message: "The identity provider is temporarily unavailable. Try again shortly."},
		{Code: CodeAdminAuthzRequired, Symbol: "ADMIN_AUTHZ_REQUIRED", Category: apperr.CategoryPermissionDenied,
			Title: "admin access", Cause: "an admin call came from neither a site-admin nor the admin CLI",
			UserSafe: true, Message: "You don't have permission to perform this administrative action. It requires the site-admin role or admin CLI access."},
		{Code: CodeRootRequired, Symbol: "ROOT_REQUIRED", Category: apperr.CategoryPermissionDenied,
			Title: "root-only grant", Cause: "a non-root admin tried a root-only grant",
			UserSafe: true, Message: "Only the root administrator can grant the {permission} permission."},
		{Code: CodeSSOJitDisabled, Symbol: "SSO_JIT_DISABLED", Category: apperr.CategoryPermissionDenied,
			Title: "SSO sign-in", Cause: "a first-seen SSO user signed in through a connection that doesn't create accounts",
			UserSafe: true, Message: "Your organization requires an administrator to create your account before you can sign in. Contact your administrator for access."},
		{Code: CodeSessionsUnavailable, Symbol: "SESSIONS_UNAVAILABLE", Category: apperr.CategoryFailedPrecondition,
			Title: "list sessions", Cause: "the sign-in service's session API isn't configured or didn't answer",
			UserSafe: true, Message: "Active sign-in sessions can't be listed right now. This list is unavailable, not empty."},
		{Code: CodeSessionRevokeUnavailable, Symbol: "SESSION_REVOKE_UNAVAILABLE", Category: apperr.CategoryFailedPrecondition,
			Title: "revoke sessions", Cause: "the sign-in service's session API isn't configured or didn't answer, so nothing was revoked",
			UserSafe: true, Message: "Signing out sessions isn't available right now, so this request had no effect. Disable the account to lock the user out at once."},
		{Code: CodeLocalAccountsUnavailable, Symbol: "LOCAL_ACCOUNTS_UNAVAILABLE", Category: apperr.CategoryFailedPrecondition,
			Title: "local accounts", Cause: "the sign-in service's admin API isn't configured, so local accounts and passwords can't be managed",
			UserSafe: true, Message: "Local accounts can't be managed on this deployment because the sign-in service isn't configured."},
		{Code: CodeUserHasPendingApprovals, Symbol: "USER_HAS_PENDING_APPROVALS", Category: apperr.CategoryFailedPrecondition,
			Title: "delete user", Cause: "the account still holds pending approval seats, which a delete would strand",
			UserSafe: true, Message: "This account can't be deleted yet: it is the assigned approver on {count} policy approval(s) still awaiting a decision ({policies}). Reassign those approvals to another approver, or withdraw the reviews, then delete the account."},
		{Code: CodeUserDeleteChecksUnavailable, Symbol: "USER_DELETE_CHECKS_UNAVAILABLE", Category: apperr.CategoryFailedPrecondition,
			Title: "delete user", Cause: "a mandatory delete or delete-preview step couldn't run; the step metadata names it",
			UserSafe: true, Message: "A required safety check ({step}) couldn't be completed, so this account's deletion can't be assessed or carried out. Nothing was changed. Try again once that service is reachable, or disable the account instead to lock the user out now."},
	}
}

var (
	regOnce sync.Once
	reg     *apperr.Registry
)

// Registry returns the service registry. Coded errors are logged through
// go-log with the trace of the request they failed.
func Registry() *apperr.Registry {
	regOnce.Do(func() {
		r, err := apperr.NewRegistry(Entries(), apperr.WithService(5), apperr.WithCodeDigits(4),
			apperr.WithLogger(logSink{log.NewLogger("identity")}))
		if err != nil {
			panic(err)
		}
		reg = r
	})
	return reg
}

// Error turns err into the gRPC error a handler returns.
func Error(ctx context.Context, err error) error {
	return apperrgrpc.Error(ctx, Registry(), err, CodeInternal, Domain)
}

// Doc is the Markdown body of docs/error-codes.md.
func Doc() string {
	return "# Error codes\n\nEvery coded gRPC error from the identity service carries an `ErrorInfo` with the symbol as\n" +
		"its reason, the domain `" + Domain + "` and the code in `codeNum`. Only user-safe messages reach the\n" +
		"caller; every other code is sent as `Code N: Internal Error`.\n\n" + Registry().Markdown()
}

var (
	errAdminAuthz   = errors.New("identity: admin access required")
	errRoot         = errors.New("identity: root required")
	errJitDisabled  = errors.New("identity: just-in-time accounts are off for this connection")
	errLocalAccount = errors.New("identity: the sign-in service admin API isn't configured")
	errPending      = errors.New("identity: the account holds pending approvals")
)

// SSOProviderUnreachable codes a failed call to the SSO broker; org names the
// organisation being set up.
func SSOProviderUnreachable(org string, cause error) error {
	return apperr.WithMeta(apperr.Coded(CodeSSOProviderUnreachable, cause), apperr.Meta("org", org))
}

// AdminAuthzRequired codes an admin call from a caller who isn't one.
func AdminAuthzRequired() error { return apperr.Coded(CodeAdminAuthzRequired, errAdminAuthz) }

// RootRequired codes a root-only grant tried by another admin.
func RootRequired(permission string) error {
	return apperr.WithMeta(apperr.Coded(CodeRootRequired, errRoot), apperr.Meta("permission", permission))
}

// SSOJitDisabled codes a refused first SSO sign-in.
func SSOJitDisabled() error { return apperr.Coded(CodeSSOJitDisabled, errJitDisabled) }

// SessionsUnavailable codes a session listing the sign-in service couldn't
// answer.
func SessionsUnavailable(cause error) error { return apperr.Coded(CodeSessionsUnavailable, cause) }

// SessionRevokeUnavailable codes a revoke the sign-in service couldn't carry
// out.
func SessionRevokeUnavailable(cause error) error {
	return apperr.Coded(CodeSessionRevokeUnavailable, cause)
}

// LocalAccountsUnavailable codes a local-account call with no sign-in
// service admin API configured.
func LocalAccountsUnavailable() error {
	return apperr.Coded(CodeLocalAccountsUnavailable, errLocalAccount)
}

// UserHasPendingApprovals codes a delete refused while the account holds
// count pending approvals; policies names them.
func UserHasPendingApprovals(count int, policies string) error {
	return apperr.WithMeta(apperr.Coded(CodeUserHasPendingApprovals, errPending),
		apperr.Meta("count", strconv.Itoa(count)), apperr.Meta("policies", policies))
}

// UserDeleteChecksUnavailable codes a mandatory delete step that couldn't
// run; step names it.
func UserDeleteChecksUnavailable(step string, cause error) error {
	return apperr.WithMeta(apperr.Coded(CodeUserDeleteChecksUnavailable, cause), apperr.Meta("step", step))
}

type logSink struct{ l log.Logger }

func (s logSink) LogCoded(ctx context.Context, code int, err error) {
	s.l.Ctx(ctx).Debug("coded error", log.F("code", code), log.F("error", err.Error()))
}
