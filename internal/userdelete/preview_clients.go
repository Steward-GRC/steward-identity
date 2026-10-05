// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

// --- owned policies -------------------------------------------------------

type grpcOwnedPolicies struct {
	c corev1.PolicyServiceClient
}

// NewGRPCOwnedPolicyLister wraps a core PolicyServiceClient as an
// OwnedPolicyLister for the delete preview.
//
// It calls PolicyService.ListPoliciesByOwner, which core documents as the
// authoritative "orphaned set" and as read-only — the same RPC the merge
// preview uses, so the delete preview counts owned policies the same way the
// merge preview does.
//
// includeRetired is TRUE: a retired policy still has an owner_user_id, so a
// delete still orphans it. Hiding retired policies would under-report the
// blast radius, and the item detail says which ones are retired.
func NewGRPCOwnedPolicyLister(c corev1.PolicyServiceClient) OwnedPolicyLister {
	return &grpcOwnedPolicies{c: c}
}

func (g *grpcOwnedPolicies) ListPoliciesByOwner(ctx context.Context, userID string) ([]OwnedPolicy, error) {
	resp, err := g.c.ListPoliciesByOwner(ctx, &corev1.ListPoliciesByOwnerRequest{
		OwnerUserId:    userID,
		IncludeRetired: true,
	})
	if err != nil {
		return nil, err
	}
	ps := resp.GetPolicies()
	out := make([]OwnedPolicy, 0, len(ps))
	for _, p := range ps {
		out = append(out, OwnedPolicy{
			ID:     p.GetId(),
			Number: p.GetNumber(),
			Title:  p.GetTitle(),
			// Policy carries no status enum; retired_at is core's policy-level
			// soft-delete stamp (RFC3339, empty = active).
			Retired: p.GetRetiredAt() != "",
		})
	}
	return out, nil
}

// --- category RACI rules, dry run ----------------------------------------

type grpcCategoryRulePreview struct {
	c corev1.CategoryServiceClient
}

// NewGRPCCategoryRulePreviewer wraps a core CategoryServiceClient as a
// CategoryRulePreviewer, calling GroupService.PurgeUserCategoryRules with
// dry_run=TRUE.
//
// This is the whole point of's RACI class: core already implements
// the dry run — its contract states that dry_run=true mutates nothing, emits no
// audit, and still returns what WOULD be removed — and identity deliberately
// did not call it, so the grants a delete drops had nowhere to be shown. There
// is no count to reimplement here.
//
// actor_user_id is deliberately left EMPTY. It exists so core can attribute the
// purge in its audit trail, and a dry run writes no audit; sending an actor for
// a read would put an admin's id on a record of something that did not happen.
//
// It reads resp.GetRules() — the per-rule rows the mutating adapter
// (NewGRPCCategoryRulePurger) drops on the floor because the delete path only
// needs the count. A preview needs the rows: "3 grants will be removed" is not
// actionable, "author on Information Security" is.
func NewGRPCCategoryRulePreviewer(c corev1.CategoryServiceClient) CategoryRulePreviewer {
	return &grpcCategoryRulePreview{c: c}
}

func (g *grpcCategoryRulePreview) PreviewUserCategoryRules(ctx context.Context, userID string) ([]RaciGrant, error) {
	resp, err := g.c.PurgeUserCategoryRules(ctx, &corev1.PurgeUserCategoryRulesRequest{
		UserId: userID,
		DryRun: true,
	})
	if err != nil {
		return nil, err
	}
	rules := resp.GetRules()
	out := make([]RaciGrant, 0, len(rules))
	for _, r := range rules {
		out = append(out, RaciGrant{
			CategoryID: r.GetCategoryId(),
			Roles:      raciRoles(r.GetRule()),
		})
	}
	// Older/partial core responses may report a count without the rows. Do not
	// silently report zero grants in that case: fall back to the count so the
	// preview's number stays truthful even when it cannot name the rows.
	if len(out) == 0 && resp.GetRemovedRules() > 0 {
		for _, cat := range resp.GetAffectedCategoryIds() {
			out = append(out, RaciGrant{CategoryID: cat})
		}
	}
	return out, nil
}

// raciRoles renders the tri-state grants that are actually ALLOWed as the RACI
// role names an admin recognises. A DENY is not a grant the account holds, so
// it is not listed as one; core's own model is R=author, A=approve, C=read,
// I=ack.
func raciRoles(r *corev1.CategoryRule) []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, pair := range []struct {
		effect corev1.GrantEffect
		name   string
	}{
		{r.GetAuthor(), "author"},
		{r.GetApprove(), "approve"},
		{r.GetRead(), "read"},
		{r.GetAck(), "ack"},
	} {
		if pair.effect == corev1.GrantEffect_GRANT_EFFECT_ALLOW {
			out = append(out, pair.name)
		}
	}
	return out
}

// --- credential lookup ----------------------------------------------------

type kratosCredentialFinder struct {
	c *kratos.Client
}

// NewKratosCredentialFinder wraps the Kratos admin client as a read-only
// CredentialFinder.
//
// It calls FindIdentity, NOT RevokeIdentity. That distinction is the reason
// CredentialFinder is a separate interface from CredentialRevoker: the revoker's
// only method deactivates the identity, kills its sessions and deletes its
// password, so a preview reusing it would perform the very action it is
// supposed to be previewing.
func NewKratosCredentialFinder(c *kratos.Client) CredentialFinder {
	return &kratosCredentialFinder{c: c}
}

func (k *kratosCredentialFinder) FindCredential(ctx context.Context, email string) (CredentialRef, error) {
	ref, err := k.c.FindIdentity(ctx, email)
	if err != nil {
		return CredentialRef{}, err
	}
	return CredentialRef{ID: ref.ID, Found: ref.Found, State: ref.State}, nil
}
