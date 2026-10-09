// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Pre-delete DRY RUN.
//
// Check (userdelete.go) is the guard that runs AT delete time and mutates:
// it refuses, revokes a credential and purges grants. Preview is its read-only
// twin — same classes, same fail-closed posture, zero writes.
//
// # Why it is a separate function and not a flag on Check
//
// Two of Check's three steps are inherently mutating. CredentialRevoker
// deactivates the Kratos identity, kills its sessions and drops its password;
// CategoryRulePurger deletes rows. A `dryRun bool` on Check would mean every
// caller of the delete path carries the ability to silently not-delete, and
// every fake in the guard's tests would have to model both modes. The preview
// instead takes its own client set, composed of read-only seams:
//
//   - ApprovalLister — reused VERBATIM from Check. It was already read-only
//     (workflow ListPendingTasks), which is why the refusal could be built on it.
//   - CategoryRulePreviewer — core PurgeUserCategoryRules with dry_run=true.
//     Not a new RPC: shipped dry_run in contracts/core v1.10.0, and its
//     contract documents that form as mutating nothing, emitting no audit, and
//     still returning the would-be-removed rules. identity deliberately did not
//     call it from the delete path; surfacing it here is exactly what
//
// asks for.
//   - OwnedPolicyLister — core ListPoliciesByOwner, already read-only.
//   - CredentialFinder — kratosadmin FindIdentity, the read-only half of
//     RevokeIdentity's step 1.
//
// # Why it fails closed
//
// was caused by nobody being able to tell "the check ran and found
// nothing" from "the check never ran". A preview is worse in that respect than
// a delete, because an admin reads it and then acts on it: a preview that
// silently omits the RACI class because core was unreachable actively tells the
// admin that no grants will be dropped. So an unwired or failing client is a
// *StepUnavailableError naming the step, which the handler maps to
// USER_DELETE_CHECKS_UNAVAILABLE (5009) — the same code and the same {step}
// metadata the delete path uses, because it is the same condition.
package userdelete

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Additional step names for the preview-only reads. StepApprovalCheck and
// StepCategoryRulePurge are shared with Check so an operator sees the same
// step label whether the delete or its preview could not run.
const (
	StepOwnedPolicies    = "owned_policies"
	StepCredentialLookup = "credential_lookup" // #nosec G101 -- a step name
)

// Item kinds, mirroring merge.Kind* but deliberately NOT the same set: a delete
// has no target account, so nothing MOVES. Each kind is blocked, orphaned, or
// removed.
const (
	KindPendingApproval = "pending_approval"
	KindOwnedPolicy     = "owned_policy"
	KindRaciGrant       = "raci_grant"
	KindAccessRow       = "access_row"
	KindCredential      = "credential"
)

// Warning codes carried on DeletionWarning.Code.
const (
	WarnBlockedPendingApprovals = "DELETE_BLOCKED_PENDING_APPROVALS"
	WarnBlockedRootProtected    = "DELETE_BLOCKED_ROOT_PROTECTED"
	WarnPoliciesOrphaned        = "POLICIES_ORPHANED"
	WarnRaciGrantsRemoved       = "RACI_GRANTS_REMOVED"
	WarnRetainedManagedGroups   = "RETAINED_MANAGED_GROUPS"
	WarnLastLocalCredential     = "LAST_LOCAL_CREDENTIAL" // #nosec G101 -- a warning code
	WarnNoLocalCredential       = "NO_LOCAL_CREDENTIAL"   // #nosec G101 -- a warning code
	WarnAlreadyDeleted          = "ALREADY_DELETED"
)

// OwnedPolicy is one policy the account owns. A delete deliberately ORPHANS
// these for admin re-assignment rather than deleting them, which
// is a visible, recoverable state — but the admin should be told the count
// before the delete, not after.
type OwnedPolicy struct {
	ID      string
	Number  string
	Title   string
	Retired bool
}

// OwnedPolicyLister reads the account's owned policies from core. Backed by
// PolicyService.ListPoliciesByOwner (see NewGRPCOwnedPolicyLister); read-only,
// so the preview cannot itself re-own anything.
type OwnedPolicyLister interface {
	ListPoliciesByOwner(ctx context.Context, userID string) ([]OwnedPolicy, error)
}

// RaciGrant is one user-subject category RACI rule the delete would purge.
// Roles is the human-readable subset of the rule's tri-state grants that are
// actually set, e.g. ["author", "approve"].
type RaciGrant struct {
	CategoryID string
	Roles      []string
}

// CategoryRulePreviewer reports the account's user-subject category RACI rules
// WITHOUT removing them — core PurgeUserCategoryRules with dry_run=true
// . Separate from CategoryRulePurger so the mutating and non-mutating
// forms cannot be confused at a call site.
type CategoryRulePreviewer interface {
	PreviewUserCategoryRules(ctx context.Context, userID string) ([]RaciGrant, error)
}

// CredentialRef is what the credential store holds for the account.
// Found=false is the normal state for a federated (SSO-only) account.
type CredentialRef struct {
	ID    string
	Found bool
	State string
}

// CredentialFinder resolves the account's credential-store identity read-only.
// *kratos.Client satisfies it via FindIdentity. It is deliberately NOT
// CredentialRevoker: that interface's only method mutates.
type CredentialFinder interface {
	FindCredential(ctx context.Context, email string) (CredentialRef, error)
}

// PreviewSteps holds the read-only clients the preview drives. A nil field
// means "refuse, this deployment cannot read that class" — never "skip".
type PreviewSteps struct {
	Approvals     ApprovalLister
	OwnedPolicies OwnedPolicyLister
	CategoryRules CategoryRulePreviewer
	Credentials   CredentialFinder
}

// Account is identity's own half of the preview input, supplied by the caller
// from store.UserDeletionPreflight. It is passed in rather than read here so
// this package stays database-free and unit-testable with fakes, exactly like
// Check.
type Account struct {
	UserID string
	Email  string
	IsRoot bool
	// DeletedAt is non-zero when the account is ALREADY tombstoned. Previewing
	// a delete of an already-deleted account is legitimate and reports
	// ALREADY_DELETED rather than erroring.
	DeletedAt time.Time
	// LocalAccount and Passkeys are identity's half of "can this account
	// authenticate without the IdP".
	LocalAccount bool
	Passkeys     int

	Roles            []string
	ScopedRoles      []string
	GroupLabels      []string
	IdpGroups        []string
	PolicyOverrides  []string
	Permissions      []string
	BreakGlassGrants int
	ManagedGroups    int

	// OtherLiveAccountsSameEmail / OtherLocalAccountsSameEmail come from the
	// store preflight. They are how the preview answers the note
	// "deleting a user's only locally-authenticable account changes how they can
	// get in" without claiming to know that two accounts are the same person.
	OtherLiveAccountsSameEmail  int
	OtherLocalAccountsSameEmail int
}

// DeletionCounts is the per-class summary. Every field is a count the preview
// actually READ; a class that could not be read is an error, never a zero.
type DeletionCounts struct {
	PendingApprovals int
	OwnedPolicies    int
	RaciGrants       int
	Roles            int
	Permissions      int
	GroupMemberships int
	IdpGroups        int
	PolicyOverrides  int
	BreakGlassGrants int
	ManagedGroups    int
}

// DeletionItem is one human-reviewable line, mirroring merge.PreviewItem.
type DeletionItem struct {
	Kind         string
	RefID        string
	Label        string
	Detail       string
	BlocksDelete bool
}

// DeletionWarning flags a consequence the admin must weigh.
type DeletionWarning struct {
	Code    string
	Message string
}

// DeletionPreview is the read-only dry-run result.
type DeletionPreview struct {
	UserID   string
	Counts   DeletionCounts
	Items    []DeletionItem
	Warnings []DeletionWarning
	// BlocksDelete is true when DeleteUser would REFUSE right now: the account
	// holds pending approval seats, or it is the protected root account.
	BlocksDelete bool
	// LocallyAuthenticable is true when the account can authenticate without
	// the IdP today — a local account, a credential in the credential store, or
	// a registered passkey.
	LocallyAuthenticable bool
}

// Preview runs every read-only pre-delete class and reports what a delete would
// affect. It mutates nothing. A nil client on ANY class is a
// *StepUnavailableError, not a skip — see the package doc.
func Preview(ctx context.Context, steps PreviewSteps, acct Account) (*DeletionPreview, error) {
	out := &DeletionPreview{UserID: acct.UserID}

	// --- root protection. Checked first and locally: DeleteUser refuses root
	// outright, so a preview that listed a blast radius for root would describe
	// a delete that can never happen.
	if acct.IsRoot {
		out.BlocksDelete = true
		out.Warnings = append(out.Warnings, DeletionWarning{
			Code:    WarnBlockedRootProtected,
			Message: "This is a root administrator account. It cannot be deleted; revoke its root role first (another root administrator must remain).",
		})
	}
	if !acct.DeletedAt.IsZero() {
		out.Warnings = append(out.Warnings, DeletionWarning{
			Code: WarnAlreadyDeleted,
			Message: fmt.Sprintf("This account was already deleted on %s. The figures below are what a delete would still affect.",
				acct.DeletedAt.UTC().Format("2006-01-02")),
		})
	}

	// --- 1. pending approvals — the class DeleteUser REFUSES on.
	if steps.Approvals == nil {
		return nil, &StepUnavailableError{Step: StepApprovalCheck, Err: errors.New("workflow client not configured")}
	}
	pending, err := steps.Approvals.ListPendingApprovals(ctx, acct.UserID)
	if err != nil {
		return nil, &StepUnavailableError{Step: StepApprovalCheck, Err: err}
	}
	out.Counts.PendingApprovals = len(pending)
	for _, p := range pending {
		label := strings.TrimSpace(p.PolicyTitle)
		if label == "" {
			label = "policy version " + p.PolicyVersionID
		}
		// StageIndex is 0-based on the wire; humans count stages from 1.
		detail := fmt.Sprintf("stage %d", p.StageIndex+1)
		if !p.DueAt.IsZero() {
			detail += ", due " + p.DueAt.UTC().Format("2006-01-02")
		}
		out.Items = append(out.Items, DeletionItem{
			Kind: KindPendingApproval, RefID: p.TaskID, Label: label,
			Detail: detail, BlocksDelete: true,
		})
	}
	if len(pending) > 0 {
		out.BlocksDelete = true
		out.Warnings = append(out.Warnings, DeletionWarning{
			Code: WarnBlockedPendingApprovals,
			Message: fmt.Sprintf("This account is the assigned approver on %d approval(s) still awaiting a decision, so the delete will be refused: %s. Reassign or withdraw them first, or disable the account instead.",
				len(pending), DescribeApprovals(pending, 0)),
		})
	}

	// --- 2. owned policies — ORPHANED by the delete, not removed.
	if steps.OwnedPolicies == nil {
		return nil, &StepUnavailableError{Step: StepOwnedPolicies, Err: errors.New("core policy client not configured")}
	}
	owned, err := steps.OwnedPolicies.ListPoliciesByOwner(ctx, acct.UserID)
	if err != nil {
		return nil, &StepUnavailableError{Step: StepOwnedPolicies, Err: err}
	}
	out.Counts.OwnedPolicies = len(owned)
	for _, p := range owned {
		detail := "owner — left unassigned for re-assignment"
		if p.Retired {
			detail = "owner — retired policy, left unassigned"
		}
		out.Items = append(out.Items, DeletionItem{
			Kind: KindOwnedPolicy, RefID: p.ID, Label: policyLabel(p), Detail: detail,
		})
	}
	if len(owned) > 0 {
		out.Warnings = append(out.Warnings, DeletionWarning{
			Code: WarnPoliciesOrphaned,
			Message: fmt.Sprintf("%d policy/policies owned by this account will be left without an owner for an administrator to re-assign. They are not deleted.",
				len(owned)),
		})
	}

	// --- 3. RACI grants —'s dry run.
	if steps.CategoryRules == nil {
		return nil, &StepUnavailableError{Step: StepCategoryRulePurge, Err: errors.New("core group client not configured")}
	}
	grants, err := steps.CategoryRules.PreviewUserCategoryRules(ctx, acct.UserID)
	if err != nil {
		return nil, &StepUnavailableError{Step: StepCategoryRulePurge, Err: err}
	}
	out.Counts.RaciGrants = len(grants)
	for _, g := range grants {
		detail := "user-subject rule — removed with the account"
		if len(g.Roles) > 0 {
			detail = strings.Join(g.Roles, ", ") + " grant — removed with the account"
		}
		out.Items = append(out.Items, DeletionItem{
			Kind: KindRaciGrant, RefID: g.CategoryID,
			Label: "category " + g.CategoryID, Detail: detail,
		})
	}
	if len(grants) > 0 {
		out.Warnings = append(out.Warnings, DeletionWarning{
			Code: WarnRaciGrantsRemoved,
			Message: fmt.Sprintf("%d category RACI grant(s) held by this account will be removed. Group- and everyone-subject rules are untouched.",
				len(grants)),
		})
	}

	// --- 4. credential.
	if steps.Credentials == nil {
		return nil, &StepUnavailableError{Step: StepCredentialLookup, Err: errors.New("credential store not configured")}
	}
	cred, err := steps.Credentials.FindCredential(ctx, acct.Email)
	if err != nil {
		return nil, &StepUnavailableError{Step: StepCredentialLookup, Err: err}
	}
	out.LocallyAuthenticable = acct.LocalAccount || acct.Passkeys > 0 || cred.Found
	credDetail := "no credential in the credential store — this account signs in via the IdP only" // #nosec G101 -- display text
	if cred.Found {
		credDetail = "credential present (state " + cred.State + ") — revoked before the account is deleted"
	}
	out.Items = append(out.Items, DeletionItem{
		Kind: KindCredential, RefID: cred.ID,
		Label: "local-login credential", Detail: credDetail,
	})
	switch {
	case !out.LocallyAuthenticable:
		out.Warnings = append(out.Warnings, DeletionWarning{
			Code:    WarnNoLocalCredential,
			Message: "This account has no local-login credential, so deleting it removes no way of signing in that the IdP does not already control.",
		})
	case acct.OtherLocalAccountsSameEmail == 0:
		// The incident in one sentence. Note the honest scope: this
		// is about the EMAIL ADDRESS, because identity cannot know that two
		// accounts belong to the same person.
		msg := "This is the only account on this email address that can sign in without the IdP. Deleting it changes how this person can get in — if the IdP is unavailable, there will be no local login for this address."
		if acct.OtherLiveAccountsSameEmail > 0 {
			msg = fmt.Sprintf("%d other live account(s) share this email address, but none of them can sign in without the IdP. Deleting this one changes how this person can get in.",
				acct.OtherLiveAccountsSameEmail)
		}
		out.Warnings = append(out.Warnings, DeletionWarning{Code: WarnLastLocalCredential, Message: msg})
	}

	// --- 5. identity-owned access rows. Local, no client, cannot fail.
	appendAccessRows(out, acct)

	return out, nil
}

// appendAccessRows fills the identity-owned access-row counts and items. These
// come from the store preflight, whose counter walks the SAME table list
// DeleteUser deletes from, so the preview cannot drift from the delete.
func appendAccessRows(out *DeletionPreview, acct Account) {
	out.Counts.Roles = len(acct.Roles) + len(acct.ScopedRoles)
	out.Counts.Permissions = len(acct.Permissions)
	out.Counts.GroupMemberships = len(acct.GroupLabels)
	out.Counts.IdpGroups = len(acct.IdpGroups)
	out.Counts.PolicyOverrides = len(acct.PolicyOverrides)
	out.Counts.BreakGlassGrants = acct.BreakGlassGrants
	out.Counts.ManagedGroups = acct.ManagedGroups

	add := func(refID, label, detail string) {
		out.Items = append(out.Items, DeletionItem{
			Kind: KindAccessRow, RefID: refID, Label: label, Detail: detail,
		})
	}
	for _, r := range acct.Roles {
		add(r, r, "global role — dropped")
	}
	for _, r := range acct.ScopedRoles {
		add(r, r, "category-scoped role — dropped")
	}
	for _, p := range acct.Permissions {
		add(p, p, "individual permission — dropped")
	}
	for _, g := range acct.GroupLabels {
		add(g, g, "group membership — dropped")
	}
	for _, g := range acct.IdpGroups {
		add(g, g, "identity provider group association — dropped")
	}
	for _, o := range acct.PolicyOverrides {
		add(o, o, "per-policy override — dropped")
	}
	if acct.BreakGlassGrants > 0 {
		add("", fmt.Sprintf("%d break-glass grant(s)", acct.BreakGlassGrants), "dropped")
	}
	// group_managers is the one class the delete does NOT clear.
	if acct.ManagedGroups > 0 {
		add("", fmt.Sprintf("%d local group-manager grant(s)", acct.ManagedGroups),
			"NOT removed by the delete — left pointing at the deleted account")
		out.Warnings = append(out.Warnings, DeletionWarning{
			Code: WarnRetainedManagedGroups,
			Message: fmt.Sprintf("This account is a local group-manager of %d group(s). DeleteUser does not remove group-manager grants, so they will remain, naming a deleted account. Revoke them by hand first.",
				acct.ManagedGroups),
		})
	}
}

// policyLabel renders a policy as `NUMBER — TITLE`, matching the merge
// preview's convention, and never as nothing.
func policyLabel(p OwnedPolicy) string {
	num, title := strings.TrimSpace(p.Number), strings.TrimSpace(p.Title)
	switch {
	case num != "" && title != "":
		return num + " — " + title
	case title != "":
		return title
	case num != "":
		return num
	default:
		return "policy " + p.ID
	}
}
