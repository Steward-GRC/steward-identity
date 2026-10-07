// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"context"

	corev1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/core/v1"
	obligationsv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/obligations/v1"
	workflowv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/workflow/v1"
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

// grpcAck adapts the generated obligations AckServiceClient to AckClient.
type grpcAck struct {
	c obligationsv1.AckServiceClient
}

// NewGRPCAck wraps an obligations AckServiceClient as an AckClient.
func NewGRPCAck(c obligationsv1.AckServiceClient) AckClient { return &grpcAck{c: c} }

var ackResolutions = map[obligationsv1.AckTransferResolution]string{
	obligationsv1.AckTransferResolution_ACK_TRANSFER_RESOLUTION_MOVED:         "moved",
	obligationsv1.AckTransferResolution_ACK_TRANSFER_RESOLUTION_KEPT_EARLIEST: "kept_earliest",
	obligationsv1.AckTransferResolution_ACK_TRANSFER_RESOLUTION_TARGET_KEPT:   "target_kept",
}

func (g *grpcAck) TransferAcknowledgments(ctx context.Context, sourceUserID, targetUserID, actorUserID string, dryRun bool, mergeOperationID string) (int, int, []AckItem, error) {
	resp, err := g.c.TransferAcknowledgments(ctx, &obligationsv1.TransferAcknowledgmentsRequest{
		SourceUserId:     sourceUserID,
		TargetUserId:     targetUserID,
		ActorUserId:      actorUserID,
		DryRun:           dryRun,
		MergeOperationId: mergeOperationID,
	})
	if err != nil {
		return 0, 0, nil, err
	}
	items := make([]AckItem, 0, len(resp.GetItems()))
	for _, it := range resp.GetItems() {
		item := AckItem{PolicyVersionID: it.GetPolicyVersionId(), Resolution: ackResolutions[it.GetResolution()]}
		if it.GetSourceAckedAt() != nil {
			item.SourceAckedAt = it.GetSourceAckedAt().AsTime()
		}
		if it.GetTargetAckedAt() != nil {
			item.TargetAckedAt = it.GetTargetAckedAt().AsTime()
		}
		items = append(items, item)
	}
	return int(resp.GetMoved()), int(resp.GetDeduped()), items, nil
}

// grpcWorkflow adapts the generated WorkflowServiceClient to WorkflowClient.
type grpcWorkflow struct {
	c workflowv1.WorkflowServiceClient
}

// NewGRPCWorkflow wraps a WorkflowServiceClient as a WorkflowClient.
func NewGRPCWorkflow(c workflowv1.WorkflowServiceClient) WorkflowClient { return &grpcWorkflow{c: c} }

func (g *grpcWorkflow) ReassignUserWorkflowItems(ctx context.Context, fromUserID, toUserID, actorUserID string, dryRun bool, mergeOperationID string) (int, int, int, error) {
	resp, err := g.c.ReassignUserWorkflowItems(ctx, &workflowv1.ReassignUserWorkflowItemsRequest{
		FromUserId:       fromUserID,
		ToUserId:         toUserID,
		ActorUserId:      actorUserID,
		DryRun:           dryRun,
		MergeOperationId: mergeOperationID,
	})
	if err != nil {
		return 0, 0, 0, err
	}
	return int(resp.GetAssignmentsReassigned()), int(resp.GetAssignmentsDeduped()), int(resp.GetRunsReassigned()), nil
}
