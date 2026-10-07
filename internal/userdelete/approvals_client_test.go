// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete_test

import (
	"context"
	"net"
	"testing"
	"time"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	workflowv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
)

type fakePendingTasks struct {
	workflowv1.UnimplementedWorkflowServiceServer
	got   *workflowv1.ListPendingTasksRequest
	actor grpcactor.Actor
	resp  *workflowv1.ListPendingTasksResponse
}

func (f *fakePendingTasks) ListPendingTasks(ctx context.Context, req *workflowv1.ListPendingTasksRequest) (*workflowv1.ListPendingTasksResponse, error) {
	f.got = req
	f.actor, _ = grpcactor.FromContext(ctx)
	return f.resp, nil
}

func TestGRPCApprovalListerReadsTheUsersPendingSeats(t *testing.T) {
	due := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	f := &fakePendingTasks{resp: &workflowv1.ListPendingTasksResponse{Tasks: []*workflowv1.PendingTask{
		{TaskId: "t1", RunId: "r1", PolicyVersionId: "v1", StageIndex: 0, DueAt: timestamppb.New(due)},
		{TaskId: "t2", RunId: "r2", PolicyVersionId: "v2", StageIndex: 2},
	}}}
	lis := bufconn.Listen(1 << 20)
	trustAll := func(context.Context, string) bool { return true }
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(grpcactor.UnaryServerInterceptor(grpcactor.WithTrust(trustAll))))
	workflowv1.RegisterWorkflowServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(grpcactor.UnaryClientInterceptor()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: "erin-id", Impersonator: "alice-id"})
	got, err := userdelete.NewGRPCApprovalLister(workflowv1.NewWorkflowServiceClient(conn)).ListPendingApprovals(ctx, "user-1")
	require.NoError(t, err)

	require.Equal(t, "user-1", f.got.GetApproverUserId())
	require.Equal(t, "erin-id", f.actor.Subject)
	require.Equal(t, "alice-id", f.actor.Impersonator)
	require.Equal(t, []userdelete.PendingApproval{
		{TaskID: "t1", RunID: "r1", PolicyVersionID: "v1", StageIndex: 0, DueAt: due},
		{TaskID: "t2", RunID: "r2", PolicyVersionID: "v2", StageIndex: 2},
	}, got)
}
