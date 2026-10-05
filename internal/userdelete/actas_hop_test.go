// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package userdelete_test

import (
	"context"
	"net"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	corev1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/core/v1"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
)

type actorCore struct {
	corev1.UnimplementedCategoryServiceServer
	seen chan grpcactor.Actor
}

func (c actorCore) PurgeUserCategoryRules(ctx context.Context, _ *corev1.PurgeUserCategoryRulesRequest) (*corev1.PurgeUserCategoryRulesResponse, error) {
	a, _ := grpcactor.FromContext(ctx)
	c.seen <- a
	return &corev1.PurgeUserCategoryRulesResponse{}, nil
}

// During act-as, core must see the target as the subject and the real admin
// as the impersonator on identity's outbound call.
func TestActAsSurvivesTheHopToCore(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	trustAll := func(context.Context, string) bool { return true }
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(grpcactor.UnaryServerInterceptor(grpcactor.WithTrust(trustAll))))
	core := actorCore{seen: make(chan grpcactor.Actor, 1)}
	corev1.RegisterCategoryServiceServer(srv, core)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(grpcactor.UnaryClientInterceptor()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx := grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: "erin-id", Impersonator: "alice-id"})
	_, err = userdelete.NewGRPCCategoryRulePurger(corev1.NewCategoryServiceClient(conn)).PurgeUserCategoryRules(ctx, "erin-id", "alice-id")
	require.NoError(t, err)
	got := <-core.seen
	require.Equal(t, "erin-id", got.Subject)
	require.Equal(t, "alice-id", got.Impersonator)
}
