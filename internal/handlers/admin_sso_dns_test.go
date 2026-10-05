// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"testing"
)

// mergeTXTLookups underpins the multi-resolver domain-verify: a customer's TXT
// lives on PUBLIC DNS, so we query public resolvers + the default one and accept
// a match from ANY. These pin the union / any-success / all-fail semantics.

func TestMergeTXTLookups_AnySuccessUnionsAndDedupes(t *testing.T) {
	ctx := context.Background()
	errLk := func(context.Context, string) ([]string, error) { return nil, errors.New("nxdomain") }
	okA := func(context.Context, string) ([]string, error) {
		return []string{"steward-verify=tok", "shared"}, nil
	}
	okB := func(context.Context, string) ([]string, error) {
		return []string{"shared", "b-only"}, nil
	}

	// One resolver errors (e.g. a public resolver can't see an internal domain),
	// another succeeds → the error must not mask the hit.
	got, err := mergeTXTLookups(ctx, "_steward-verify.example.com", errLk, okA)
	if err != nil {
		t.Fatalf("any-success must not error; got %v", err)
	}
	found := false
	for _, r := range got {
		if r == "steward-verify=tok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the matching record in the union; got %v", got)
	}

	// Records seen from multiple resolvers are deduped.
	got2, err := mergeTXTLookups(ctx, "n", okA, okB)
	if err != nil {
		t.Fatal(err)
	}
	shared := 0
	for _, r := range got2 {
		if r == "shared" {
			shared++
		}
	}
	if shared != 1 {
		t.Errorf("expected 'shared' deduped to 1, got %d in %v", shared, got2)
	}
}

func TestMergeTXTLookups_AllFailReturnsError(t *testing.T) {
	ctx := context.Background()
	errLk := func(context.Context, string) ([]string, error) { return nil, errors.New("boom") }
	if _, err := mergeTXTLookups(ctx, "n", errLk, errLk); err == nil {
		t.Fatal("all-fail must return an error (so VerifyDomain reports unverified)")
	}
}
