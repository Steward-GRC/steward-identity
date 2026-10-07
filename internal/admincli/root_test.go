// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

func TestAuditContextCarriesTheOperatorLabel(t *testing.T) {
	opt := rootCommandOptions{envLookup: func(k string) string { return map[string]string{"AUDIT_USER": "alice"}[k] }}
	ctx, err := withAuditContext(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	md, _ := metadata.FromOutgoingContext(ctx)
	if got := md.Get(OperatorMetadataKey); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("%s = %v, want [alice]", OperatorMetadataKey, got)
	}
}

func TestTLSIsRequiredUnlessInsecureIsSet(t *testing.T) {
	dir := t.TempDir()
	opt := rootCommandOptions{envLookup: func(k string) string {
		return map[string]string{envCertDir: dir}[k]
	}}
	if _, err := transportCredentials(opt); err == nil {
		t.Fatal("a missing client certificate must fail the dial")
	}
	opt.envLookup = func(k string) string { return map[string]string{envInsecure: "1"}[k] }
	if _, err := transportCredentials(opt); err != nil {
		t.Fatalf("insecure dev mode: %v", err)
	}
}

// identity-admin runs in the identity pod and sends the pod's workload token,
// so identity's caller authentication admits it.
func TestDialSendsTheWorkloadTokenWhenOneIsMounted(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []string, 1)
	srv := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		got <- md.Get("authorization")
		return h(ctx, req)
	}))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("tok-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{envInsecure: "1", envIdentityGRPCAddr: lis.Addr().String(), "WORKLOAD_TOKEN_FILE": tok}
	opt := rootCommandOptions{envLookup: func(k string) string { return env[k] }}
	conn, err := dialIdentity(opt)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	if a := <-got; len(a) != 1 || a[0] != "Bearer tok-1" {
		t.Fatalf("authorization = %v, want [Bearer tok-1]", a)
	}

	env["WORKLOAD_TOKEN_FILE"] = filepath.Join(t.TempDir(), "missing")
	if _, err := dialIdentity(opt); err == nil {
		t.Fatal("a token file that can't be read must fail the dial")
	}
}
