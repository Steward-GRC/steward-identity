// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/merge"
	"github.com/Steward-GRC/steward-identity/internal/safecast"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PreviewAccountMerge is the read-only dry-run: it reports exactly
// what a merge of source into target would move. It mutates nothing.
func (h *AdminHandler) PreviewAccountMerge(ctx context.Context, req *identityv1.PreviewAccountMergeRequest) (*identityv1.PreviewAccountMergeResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	if h.merge == nil {
		return nil, status.Error(codes.Unavailable, "account merge is not configured")
	}
	if req.GetSourceUserId() == "" || req.GetTargetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "source_user_id and target_user_id are required")
	}
	preview, err := h.merge.Preview(ctx, req.GetSourceUserId(), req.GetTargetUserId())
	if err != nil {
		return nil, mergeStatusErr(err)
	}
	return &identityv1.PreviewAccountMergeResponse{Preview: previewToProto(preview)}, nil
}

// MergeAccounts performs the irreversible, orchestrated,
// idempotent + resumable merge and tombstones the source. Step failures surface
// as a status=PARTIAL response (re-runnable), not an RPC error; only structural
// failures (bad ids, guards, unconfigured) return an error.
func (h *AdminHandler) MergeAccounts(ctx context.Context, req *identityv1.MergeAccountsRequest) (*identityv1.MergeAccountsResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if h.merge == nil {
		return nil, status.Error(codes.Unavailable, "account merge is not configured")
	}
	if req.GetSourceUserId() == "" || req.GetTargetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "source_user_id and target_user_id are required")
	}
	// The audit actor is resolved from the admin auth path (gateway user id or
	// admin CLI operator label), NOT trusted from the request body.
	res, err := h.merge.Execute(ctx, req.GetSourceUserId(), req.GetTargetUserId(),
		actor.ActorUserID, actor.ActorExternal, req.GetConfirmPrivileged(), req.GetIdempotencyKey())
	if err != nil {
		return nil, mergeStatusErr(err)
	}
	// A completed merge leaves the source in no groups/audiences — let
	// the obligations service purge any acks it still thinks the source owes
	// (best-effort; the reconcile is idempotent and the ack transfer already ran).
	if res.Status == "completed" {
		h.emitMembershipChanged(ctx, req.GetSourceUserId())
	}
	return resultToProto(res), nil
}

// mergeStatusErr maps orchestrator/store errors to gRPC status. A downstream
// gRPC status error passes through unchanged so the originating service's code
// relays to the client; the privileged-confirm sentinel becomes
// FailedPrecondition; store sentinels map via statusFromStoreErr.
func mergeStatusErr(err error) error {
	if errors.Is(err, merge.ErrPrivilegedConfirmRequired) {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	if _, ok := status.FromError(err); ok {
		// Already a gRPC status (e.g. Unavailable/PermissionDenied from a
		// downstream service) — relay verbatim.
		if s, _ := status.FromError(err); s.Code() != codes.Unknown {
			return err
		}
	}
	return statusFromStoreErr(err)
}

func mergeItemKindToProto(kind string) identityv1.MergeItemKind {
	switch kind {
	case merge.KindPolicyOwner:
		return identityv1.MergeItemKind_MERGE_ITEM_KIND_POLICY_OWNER
	case merge.KindRaciGrant:
		return identityv1.MergeItemKind_MERGE_ITEM_KIND_RACI_GRANT
	case merge.KindAcknowledgment:
		return identityv1.MergeItemKind_MERGE_ITEM_KIND_ACKNOWLEDGMENT
	case merge.KindWorkflowItem:
		return identityv1.MergeItemKind_MERGE_ITEM_KIND_WORKFLOW_ITEM
	case merge.KindPreference:
		return identityv1.MergeItemKind_MERGE_ITEM_KIND_PREFERENCE
	default:
		return identityv1.MergeItemKind_MERGE_ITEM_KIND_UNSPECIFIED
	}
}

func mergeCountsToProto(c merge.Counts) *identityv1.MergeCounts {
	return &identityv1.MergeCounts{
		PoliciesOwned:          safecast.Int32(c.PoliciesOwned),
		RaciGrants:             safecast.Int32(c.RaciGrants),
		AcknowledgmentsMoved:   safecast.Int32(c.AcksMoved),
		AcknowledgmentsDeduped: safecast.Int32(c.AcksDeduped),
		WorkflowItems:          safecast.Int32(c.WorkflowItems),
		Preferences:            safecast.Int32(c.Preferences),
	}
}

func previewToProto(p *merge.Preview) *identityv1.AccountMergePreview {
	out := &identityv1.AccountMergePreview{
		SourceUserId:              p.SourceUserID,
		TargetUserId:              p.TargetUserID,
		Counts:                    mergeCountsToProto(p.Counts),
		RequiresPrivilegedConfirm: p.RequiresPrivilegedConfirm,
	}
	for _, it := range p.Items {
		out.Items = append(out.Items, &identityv1.MergePreviewItem{
			Kind:   mergeItemKindToProto(it.Kind),
			RefId:  it.RefID,
			Label:  it.Label,
			Detail: it.Detail,
		})
	}
	for _, w := range p.Warnings {
		out.Warnings = append(out.Warnings, &identityv1.MergeWarning{Code: w.Code, Message: w.Message})
	}
	return out
}

func mergeStatusToProto(s string) identityv1.MergeStatus {
	switch s {
	case "completed":
		return identityv1.MergeStatus_MERGE_STATUS_COMPLETED
	case "partial":
		return identityv1.MergeStatus_MERGE_STATUS_PARTIAL
	case "failed":
		return identityv1.MergeStatus_MERGE_STATUS_FAILED
	default:
		return identityv1.MergeStatus_MERGE_STATUS_UNSPECIFIED
	}
}

func mergeStepStatusToProto(s string) identityv1.MergeStepStatus {
	switch s {
	case "pending":
		return identityv1.MergeStepStatus_MERGE_STEP_STATUS_PENDING
	case "completed":
		return identityv1.MergeStepStatus_MERGE_STEP_STATUS_COMPLETED
	case "failed":
		return identityv1.MergeStepStatus_MERGE_STEP_STATUS_FAILED
	case "skipped":
		return identityv1.MergeStepStatus_MERGE_STEP_STATUS_SKIPPED
	default:
		return identityv1.MergeStepStatus_MERGE_STEP_STATUS_UNSPECIFIED
	}
}

func resultToProto(r *merge.Result) *identityv1.MergeAccountsResponse {
	out := &identityv1.MergeAccountsResponse{
		MergeOperationId: r.MergeOperationID,
		Status:           mergeStatusToProto(r.Status),
		Counts:           mergeCountsToProto(r.Counts),
	}
	for _, st := range r.Steps {
		out.Steps = append(out.Steps, &identityv1.MergeStepResult{
			Step:   st.Step,
			Status: mergeStepStatusToProto(st.Status),
			Detail: st.Detail,
			Error:  st.Error,
		})
	}
	return out
}
