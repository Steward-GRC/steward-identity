// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package merge_test

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

	obligationsv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/obligations/v1"
	workflowv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-identity/internal/merge"
)

type fakeAck struct {
	obligationsv1.UnimplementedAckServiceServer
	got   *obligationsv1.TransferAcknowledgmentsRequest
	actor grpcactor.Actor
	resp  *obligationsv1.TransferAcknowledgmentsResponse
}

func (f *fakeAck) TransferAcknowledgments(ctx context.Context, req *obligationsv1.TransferAcknowledgmentsRequest) (*obligationsv1.TransferAcknowledgmentsResponse, error) {
	f.got = req
	f.actor, _ = grpcactor.FromContext(ctx)
	return f.resp, nil
}

type fakeWorkflow struct {
	workflowv1.UnimplementedWorkflowServiceServer
	got   *workflowv1.ReassignUserWorkflowItemsRequest
	actor grpcactor.Actor
	resp  *workflowv1.ReassignUserWorkflowItemsResponse
}

func (f *fakeWorkflow) ReassignUserWorkflowItems(ctx context.Context, req *workflowv1.ReassignUserWorkflowItemsRequest) (*workflowv1.ReassignUserWorkflowItemsResponse, error) {
	f.got = req
	f.actor, _ = grpcactor.FromContext(ctx)
	return f.resp, nil
}

// dialFake serves register on an in-process listener behind go-grpc-actor's
// server interceptor and returns a client connection that forwards the actor,
// as identity's own dial does.
func dialFake(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	trustAll := func(context.Context, string) bool { return true }
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(grpcactor.UnaryServerInterceptor(grpcactor.WithTrust(trustAll))))
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(grpcactor.UnaryClientInterceptor()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func actAs() context.Context {
	return grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: "erin-id", Impersonator: "alice-id"})
}

func TestGRPCAckSendsTheTransferAndForwardsTheActor(t *testing.T) {
	src := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	tgt := time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)
	f := &fakeAck{resp: &obligationsv1.TransferAcknowledgmentsResponse{Moved: 2, Deduped: 1, Items: []*obligationsv1.AckTransferItem{
		{PolicyVersionId: "v1", SourceAckedAt: timestamppb.New(src), Resolution: obligationsv1.AckTransferResolution_ACK_TRANSFER_RESOLUTION_MOVED},
		{PolicyVersionId: "v2", SourceAckedAt: timestamppb.New(src), TargetAckedAt: timestamppb.New(tgt), Resolution: obligationsv1.AckTransferResolution_ACK_TRANSFER_RESOLUTION_KEPT_EARLIEST},
		{PolicyVersionId: "v3", Resolution: obligationsv1.AckTransferResolution_ACK_TRANSFER_RESOLUTION_TARGET_KEPT},
	}}}
	conn := dialFake(t, func(s *grpc.Server) { obligationsv1.RegisterAckServiceServer(s, f) })

	moved, deduped, items, err := merge.NewGRPCAck(obligationsv1.NewAckServiceClient(conn)).
		TransferAcknowledgments(actAs(), "src-id", "tgt-id", "alice-id", true, "op-1")
	require.NoError(t, err)

	require.Equal(t, "src-id", f.got.GetSourceUserId())
	require.Equal(t, "tgt-id", f.got.GetTargetUserId())
	require.Equal(t, "alice-id", f.got.GetActorUserId())
	require.True(t, f.got.GetDryRun())
	require.Equal(t, "op-1", f.got.GetMergeOperationId())
	require.Equal(t, "erin-id", f.actor.Subject)
	require.Equal(t, "alice-id", f.actor.Impersonator)

	require.Equal(t, 2, moved)
	require.Equal(t, 1, deduped)
	require.Equal(t, []merge.AckItem{
		{PolicyVersionID: "v1", Resolution: "moved", SourceAckedAt: src},
		{PolicyVersionID: "v2", Resolution: "kept_earliest", SourceAckedAt: src, TargetAckedAt: tgt},
		{PolicyVersionID: "v3", Resolution: "target_kept"},
	}, items)
}

func TestGRPCWorkflowSendsTheReassignAndForwardsTheActor(t *testing.T) {
	f := &fakeWorkflow{resp: &workflowv1.ReassignUserWorkflowItemsResponse{AssignmentsReassigned: 3, AssignmentsDeduped: 1, RunsReassigned: 2, Total: 6}}
	conn := dialFake(t, func(s *grpc.Server) { workflowv1.RegisterWorkflowServiceServer(s, f) })

	reassigned, deduped, runs, err := merge.NewGRPCWorkflow(workflowv1.NewWorkflowServiceClient(conn)).
		ReassignUserWorkflowItems(actAs(), "src-id", "tgt-id", "alice-id", false, "op-2")
	require.NoError(t, err)

	require.Equal(t, "src-id", f.got.GetFromUserId())
	require.Equal(t, "tgt-id", f.got.GetToUserId())
	require.Equal(t, "alice-id", f.got.GetActorUserId())
	require.False(t, f.got.GetDryRun())
	require.Equal(t, "op-2", f.got.GetMergeOperationId())
	require.Equal(t, "erin-id", f.actor.Subject)
	require.Equal(t, "alice-id", f.actor.Impersonator)
	require.Equal(t, [3]int{3, 1, 2}, [3]int{reassigned, deduped, runs})
}
