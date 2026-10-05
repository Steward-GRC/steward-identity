// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"

	"github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/safecast"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
)

// WithOwnedPolicyLister wires the core-backed read of the policies a delete
// would ORPHAN,. Nil leaves PreviewUserDeletion
// declining with errcodes.UserDeleteChecksUnavailable rather than showing a
// preview with the owned-policy class silently missing; returns the handler for
// chaining.
func (h *AdminHandler) WithOwnedPolicyLister(l userdelete.OwnedPolicyLister) *AdminHandler {
	h.ownedPolicies = l
	return h
}

// WithCategoryRulePreviewer wires the DRY RUN of core's user-subject category
// RACI rule purge's dry_run=true). It is a separate seam from
// WithCategoryRulePurger because that one deletes rows; returns the handler for
// chaining.
func (h *AdminHandler) WithCategoryRulePreviewer(p userdelete.CategoryRulePreviewer) *AdminHandler {
	h.categoryRulePrev = p
	return h
}

// WithCredentialFinder wires the READ-ONLY credential-store lookup used by the
// delete preview. It is a separate seam from WithCredentialRevoker because that
// one deactivates the identity, kills its sessions and deletes its password —
// i.e. performs the action being previewed; returns the handler for chaining.
func (h *AdminHandler) WithCredentialFinder(f userdelete.CredentialFinder) *AdminHandler {
	h.credentialFinder = f
	return h
}

// PreviewUserDeletion is the read-only dry run of DeleteUser: it
// reports the blast radius before the admin confirms. It mutates NOTHING.
//
// made the dangerous outcome impossible rather than merely warned
// about — DeleteUser now REFUSES while the account holds pending approval
// seats. But the admin learns that only at the moment they click delete, as a
// refusal, and the classes that are NOT refusals had nowhere to be shown at
// all: the policies the delete deliberately orphans, the RACI grants it purges,
// the access rows it drops, and whether the account holds this person's only
// locally-authenticable credential.
//
// Like PreviewAccountMerge it emits no audit event (a read-only dry run is not
// an action), so the resolved actor is deliberately discarded.
func (h *AdminHandler) PreviewUserDeletion(ctx context.Context, req *identityv1.PreviewUserDeletionRequest) (*identityv1.PreviewUserDeletionResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	// One read-only pass over identity's own tables. An ALREADY-tombstoned
	// account is a legitimate input: GetUser stays tombstone-blind, so
	// previewing a delete of a deleted account reports ALREADY_DELETED instead
	// of a confusing NotFound.
	pf, err := h.store.UserDeletionPreflight(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	preview, err := userdelete.Preview(ctx, userdelete.PreviewSteps{
		Approvals:     h.approvals,
		OwnedPolicies: h.ownedPolicies,
		CategoryRules: h.categoryRulePrev,
		Credentials:   h.credentialFinder,
	}, accountFromPreflight(pf))
	if err != nil {
		return nil, previewDeletionErr(ctx, id.String(), err)
	}
	return &identityv1.PreviewUserDeletionResponse{Preview: deletionPreviewToProto(preview)}, nil
}

// accountFromPreflight projects the store preflight onto the DB-free Account
// the userdelete package works with. The mapping is where the two definitions
// of each class meet, so it is deliberately explicit rather than a struct copy:
// several fields come from the RAW row counts rather than from the hydrated
// User, because hydrateUser under-reports two of them (see
// store.UserAccessRowCounts).
func accountFromPreflight(pf store.UserDeletionPreflight) userdelete.Account {
	u := pf.User
	acct := userdelete.Account{
		UserID:       u.ID.String(),
		Email:        u.Email,
		IsRoot:       u.IsRoot,
		LocalAccount: u.LocalAccount,
		Passkeys:     pf.Passkeys,
		Roles:        append([]string{}, u.Roles...),
		IdpGroups:    append([]string{}, u.IdpGroups...),
		Permissions:  append([]string{}, pf.Permissions...),
		// BreakGlassGrants is the RAW row count, not len(ActiveBreakGlass):
		// that method filters expires_at > now() and de-duplicates by policy
		// number, while the delete removes every row.
		BreakGlassGrants:            pf.AccessRows.BreakGlassGrants,
		ManagedGroups:               pf.AccessRows.ManagedGroups,
		OtherLiveAccountsSameEmail:  pf.OtherLiveAccountsSameEmail,
		OtherLocalAccountsSameEmail: pf.OtherLocalAccountsSameEmail,
	}
	if u.DeletedAt != nil {
		acct.DeletedAt = *u.DeletedAt
	}
	for _, sr := range u.ScopedRoles {
		acct.ScopedRoles = append(acct.ScopedRoles, sr.Role+" ("+sr.Category+")")
	}
	for _, gid := range u.Groups {
		if name := pf.GroupLabels[gid]; name != "" {
			acct.GroupLabels = append(acct.GroupLabels, name)
			continue
		}
		// Never render a membership as nothing.
		acct.GroupLabels = append(acct.GroupLabels, gid.String())
	}
	for _, ov := range u.PolicyOverrides {
		acct.PolicyOverrides = append(acct.PolicyOverrides, ov.PolicyNumber+" ("+ov.Effect+")")
	}
	return acct
}

// previewDeletionErr maps a preview failure to a coded, user-safe error.
//
// It REUSES errcodes.UserDeleteChecksUnavailable (5009) with the distinguishing
// {step} field rather than registering a new code, for the same reason
// reused it with step=category_rule_purge: the condition is identical — a
// mandatory pre-delete class could not be read — and an operator needs the step
// name, not a second code that means the same thing. The preview adds two step
// values (owned_policies, credential_lookup) and shares the other two with the
// delete path, so a 5009 reads the same whether it came from the preview or the
// delete itself.
func previewDeletionErr(ctx context.Context, userID string, err error) error {
	l := logger.Ctx(ctx)
	if unavailable, ok := errors.AsType[*userdelete.StepUnavailableError](err); ok {
		l.Error(unavailable.Err, "preview user deletion: a mandatory pre-delete class could not be read", log.F("user_id", userID), log.F("step", unavailable.Step))
		return errcodes.Error(ctx, errcodes.UserDeleteChecksUnavailable(unavailable.Step, unavailable.Err))
	}
	// Unreachable today (Preview returns only StepUnavailableError), but a
	// future class must not degrade into a generic Internal.
	l.Error(err, "preview user deletion failed", log.F("user_id", userID))
	return errcodes.Error(ctx, errcodes.UserDeleteChecksUnavailable("pre_delete_preview", err))
}

func deletionItemKindToProto(kind string) identityv1.DeletionItemKind {
	switch kind {
	case userdelete.KindPendingApproval:
		return identityv1.DeletionItemKind_DELETION_ITEM_KIND_PENDING_APPROVAL
	case userdelete.KindOwnedPolicy:
		return identityv1.DeletionItemKind_DELETION_ITEM_KIND_OWNED_POLICY
	case userdelete.KindRaciGrant:
		return identityv1.DeletionItemKind_DELETION_ITEM_KIND_RACI_GRANT
	case userdelete.KindAccessRow:
		return identityv1.DeletionItemKind_DELETION_ITEM_KIND_ACCESS_ROW
	case userdelete.KindCredential:
		return identityv1.DeletionItemKind_DELETION_ITEM_KIND_CREDENTIAL
	default:
		return identityv1.DeletionItemKind_DELETION_ITEM_KIND_UNSPECIFIED
	}
}

func deletionCountsToProto(c userdelete.DeletionCounts) *identityv1.UserDeletionCounts {
	return &identityv1.UserDeletionCounts{
		PendingApprovals: safecast.Int32(c.PendingApprovals),
		OwnedPolicies:    safecast.Int32(c.OwnedPolicies),
		RaciGrants:       safecast.Int32(c.RaciGrants),
		Roles:            safecast.Int32(c.Roles),
		Permissions:      safecast.Int32(c.Permissions),
		GroupMemberships: safecast.Int32(c.GroupMemberships),
		IdpGroups:        safecast.Int32(c.IdpGroups),
		PolicyOverrides:  safecast.Int32(c.PolicyOverrides),
		BreakGlassGrants: safecast.Int32(c.BreakGlassGrants),
		ManagedGroups:    safecast.Int32(c.ManagedGroups),
	}
}

func deletionPreviewToProto(p *userdelete.DeletionPreview) *identityv1.UserDeletionPreview {
	out := &identityv1.UserDeletionPreview{
		UserId:               p.UserID,
		Counts:               deletionCountsToProto(p.Counts),
		BlocksDelete:         p.BlocksDelete,
		LocallyAuthenticable: p.LocallyAuthenticable,
	}
	for _, it := range p.Items {
		out.Items = append(out.Items, &identityv1.UserDeletionPreviewItem{
			Kind:         deletionItemKindToProto(it.Kind),
			RefId:        it.RefID,
			Label:        it.Label,
			Detail:       it.Detail,
			BlocksDelete: it.BlocksDelete,
		})
	}
	for _, w := range p.Warnings {
		out.Warnings = append(out.Warnings, &identityv1.UserDeletionWarning{
			Code: w.Code, Message: w.Message,
		})
	}
	return out
}
