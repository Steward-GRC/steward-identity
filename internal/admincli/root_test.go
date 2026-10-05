// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"context"
	"testing"

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
