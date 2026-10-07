// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete

import (
	"context"

	workflowv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/workflow/v1"
)

// grpcApprovals adapts the generated WorkflowServiceClient to ApprovalLister.
type grpcApprovals struct {
	c workflowv1.WorkflowServiceClient
}

// NewGRPCApprovalLister wraps a WorkflowServiceClient as an ApprovalLister. It
// reads the account's seats with WorkflowService.ListPendingTasks. Workflow
// carries no policy title, so the refusal names each seat by its version id.
func NewGRPCApprovalLister(c workflowv1.WorkflowServiceClient) ApprovalLister {
	return &grpcApprovals{c: c}
}

func (g *grpcApprovals) ListPendingApprovals(ctx context.Context, userID string) ([]PendingApproval, error) {
	resp, err := g.c.ListPendingTasks(ctx, &workflowv1.ListPendingTasksRequest{ApproverUserId: userID})
	if err != nil {
		return nil, err
	}
	out := make([]PendingApproval, 0, len(resp.GetTasks()))
	for _, t := range resp.GetTasks() {
		a := PendingApproval{TaskID: t.GetTaskId(), RunID: t.GetRunId(), PolicyVersionID: t.GetPolicyVersionId(), StageIndex: t.GetStageIndex()}
		if t.GetDueAt() != nil {
			a.DueAt = t.GetDueAt().AsTime()
		}
		out = append(out, a)
	}
	return out, nil
}
