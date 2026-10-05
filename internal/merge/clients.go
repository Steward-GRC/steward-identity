// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/core/v1"
)

// grpcCore adapts the generated core PolicyServiceClient to CoreClient.
type grpcCore struct{ c corev1.PolicyServiceClient }

// NewGRPCCore wraps a core PolicyServiceClient as a CoreClient.
func NewGRPCCore(c corev1.PolicyServiceClient) CoreClient { return &grpcCore{c: c} }

func (g *grpcCore) ListPoliciesByOwner(ctx context.Context, ownerUserID string, includeRetired bool) ([]PolicyRef, error) {
	resp, err := g.c.ListPoliciesByOwner(ctx, &corev1.ListPoliciesByOwnerRequest{
		OwnerUserId:    ownerUserID,
		IncludeRetired: includeRetired,
	})
	if err != nil {
		return nil, err
	}
	out := make([]PolicyRef, 0, len(resp.GetPolicies()))
	for _, p := range resp.GetPolicies() {
		out = append(out, PolicyRef{ID: p.GetId(), Number: p.GetNumber(), Title: p.GetTitle()})
	}
	return out, nil
}

// GetPolicyVersion resolves a policy version id to the version plus its owning
// policy's number/title, for the acknowledgement preview label.
//
// It costs two existing reads — GetPolicyVersion carries only policy_id and
// version_no, so the number and title come from GetPolicy — deliberately, to
// avoid a contracts change during release close-out. A batch
// ResolvePolicyVersionLabels RPC on core is the follow-up if the N reads ever
// matter; this path runs on an admin-initiated dry-run over one user's
// acknowledgements.
//
// A version or policy that resolves to nothing yields a zero/partial
// PolicyVersionRef rather than an error, so the caller falls back to the raw id
// instead of losing a preview row.
func (g *grpcCore) GetPolicyVersion(ctx context.Context, versionID string) (PolicyVersionRef, error) {
	vresp, err := g.c.GetPolicyVersion(ctx, &corev1.GetPolicyVersionRequest{Id: versionID})
	if err != nil {
		return PolicyVersionRef{}, err
	}
	v := vresp.GetVersion()
	if v == nil {
		return PolicyVersionRef{}, nil
	}
	ref := PolicyVersionRef{ID: v.GetId(), PolicyID: v.GetPolicyId(), VersionNo: v.GetVersionNo()}
	if ref.PolicyID == "" {
		return ref, nil
	}
	presp, err := g.c.GetPolicy(ctx, &corev1.GetPolicyRequest{Id: ref.PolicyID})
	if err != nil {
		return ref, err
	}
	if pol := presp.GetPolicy(); pol != nil {
		ref.PolicyNumber = pol.GetNumber()
		ref.PolicyTitle = pol.GetTitle()
	}
	return ref, nil
}

func (g *grpcCore) ReassignUserPolicies(ctx context.Context, fromUserID, toUserID, actorUserID string) ([]string, int, int, error) {
	resp, err := g.c.ReassignUserPolicies(ctx, &corev1.ReassignUserPoliciesRequest{
		FromUserId:  fromUserID,
		ToUserId:    toUserID,
		ActorUserId: actorUserID,
	})
	if err != nil {
		return nil, 0, 0, err
	}
	return resp.GetReassignedPolicyIds(), int(resp.GetReassignedOwnerCount()), int(resp.GetReassignedAuthorGrants()), nil
}
