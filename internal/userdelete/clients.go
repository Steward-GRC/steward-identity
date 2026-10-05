// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/core/v1"
)

// grpcCategoryRules adapts the generated core CategoryServiceClient to
// CategoryRulePurger.
type grpcCategoryRules struct {
	c corev1.CategoryServiceClient
}

// NewGRPCCategoryRulePurger wraps a core CategoryServiceClient as a
// CategoryRulePurger.
//
// It calls GroupService.PurgeUserCategoryRules with dry_run=false.
// That RPC exists because nothing else on the core contract can express
// "remove this user's rules, no target": GetCategoryRuleset/SetCategoryRuleset
// are per-category read-modify-write with no by-subject read, so doing it from
// here would mean walking the whole category tree and racing every ruleset
// edit, and PolicyService.ReassignUserPolicies REQUIRES a to_user_id that
// differs from from_user_id — a delete has none.
//
// The dry_run=true form is deliberately NOT used here: previewing the grants a
// delete is about to drop belongs to the delete preview, not to
// the step that performs it.
func NewGRPCCategoryRulePurger(c corev1.CategoryServiceClient) CategoryRulePurger {
	return &grpcCategoryRules{c: c}
}

func (g *grpcCategoryRules) PurgeUserCategoryRules(ctx context.Context, userID, actorUserID string) (PurgeResult, error) {
	resp, err := g.c.PurgeUserCategoryRules(ctx, &corev1.PurgeUserCategoryRulesRequest{
		UserId:      userID,
		ActorUserId: actorUserID,
	})
	if err != nil {
		return PurgeResult{}, err
	}
	return PurgeResult{
		RemovedRules:        int(resp.GetRemovedRules()),
		AffectedCategoryIDs: resp.GetAffectedCategoryIds(),
	}, nil
}
