// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

type hintsKey struct{}

// incomingMDCtx carries a sign-in's claims the way the tests name them
// (x-identity-email and the rest); hinted turns them into request fields.
func incomingMDCtx(parent context.Context, kv map[string]string) context.Context {
	return context.WithValue(parent, hintsKey{}, kv)
}

// hintedRead is the read handler with the claims from incomingMDCtx copied
// into the ResolveClaims and JitProvisionByEmail requests.
type hintedRead struct{ *handlers.ReadHandler }

func hinted(h *handlers.ReadHandler) hintedRead { return hintedRead{h} }

func hintsOf(ctx context.Context) map[string]string {
	kv, _ := ctx.Value(hintsKey{}).(map[string]string)
	return kv
}

func splitGroups(s string) []string {
	var out []string
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func (h hintedRead) ResolveClaims(ctx context.Context, req *identityv1.ResolveClaimsRequest) (*identityv1.ResolveClaimsResponse, error) {
	if kv := hintsOf(ctx); kv != nil {
		r := proto.Clone(req).(*identityv1.ResolveClaimsRequest)
		set := func(dst *string, k string) {
			if *dst == "" {
				*dst = kv[k]
			}
		}
		set(&r.Email, "x-identity-email")
		set(&r.Name, "x-identity-name")
		set(&r.FirstName, "x-identity-first-name")
		set(&r.LastName, "x-identity-last-name")
		set(&r.PreferredUsername, "x-identity-preferred-username")
		set(&r.ConnectionAlias, "x-identity-idp-alias")
		if len(r.IdpGroups) == 0 {
			r.IdpGroups = splitGroups(kv["x-identity-idp-groups"])
		}
		req = r
	}
	return h.ReadHandler.ResolveClaims(ctx, req)
}

// TestResolveClaimsAdoptsPreCreatedLocalUser is the core case:
// a local user pre-created via PreCreateLocalUser (no external_subject) must
// be adopted — not JIT-duplicated — on first federated login when the token
// email matches. The same row ID must be returned.
func TestResolveClaimsAdoptsPreCreatedLocalUser(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Pre-create a local user (no external_subject yet).
	created, err := s.PreCreateLocalUser(ctx, "local.reader", "local.reader@corp.example.com", "Local Reader")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	if created.ExternalSubject != "" {
		t.Fatalf("pre-check: ExternalSubject must be empty, got %q", created.ExternalSubject)
	}

	// Simulate a first federated login: ResolveClaims with a new external_subject
	// and an email hint matching the pre-created user.
	const newSub = "kc-adopt-sub-001"
	h := hinted(handlers.NewReadHandler(s))

	// Build a context with x-identity-email forwarded (as the gateway would do).
	adoptCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email": "local.reader@corp.example.com",
		"x-identity-name":  "Local Reader",
	})

	resp, err := h.ResolveClaims(adoptCtx, &identityv1.ResolveClaimsRequest{
		ExternalSubject: newSub,
	})
	if err != nil {
		t.Fatalf("ResolveClaims (adopt): %v", err)
	}
	if resp.User == nil {
		t.Fatal("nil user in response")
	}

	// SAME row id — no new user was created.
	if resp.User.Id != created.ID.String() {
		t.Fatalf("expected adopted user ID %s, got %s (a new row was created instead of adopting)",
			created.ID.String(), resp.User.Id)
	}

	// A second call with the same subject must still return the same row
	// (normal GetUserByExternalSubject path now, since the subject is set).
	resp2, err := h.ResolveClaims(ctx, &identityv1.ResolveClaimsRequest{
		ExternalSubject: newSub,
	})
	if err != nil {
		t.Fatalf("ResolveClaims (2nd call): %v", err)
	}
	if resp2.User.Id != created.ID.String() {
		t.Fatalf("2nd call: expected same user ID %s, got %s", created.ID.String(), resp2.User.Id)
	}
}

// TestResolveClaimsAdoptsByUsername verifies that adoption also works when the
// token carries a preferred_username hint (x-identity-preferred-username) that
// matches the pre-created user's username, even if emails differ.
func TestResolveClaimsAdoptsByUsername(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.PreCreateLocalUser(ctx, "uname.reader", "uname.reader@corp.example.com", "Uname Reader")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}

	const newSub = "kc-adopt-sub-uname-002"
	h := hinted(handlers.NewReadHandler(s))

	// Email in token is different; username matches.
	adoptCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email":              "different@email.example.net",
		"x-identity-preferred-username": "uname.reader",
	})

	resp, err := h.ResolveClaims(adoptCtx, &identityv1.ResolveClaimsRequest{
		ExternalSubject: newSub,
	})
	if err != nil {
		t.Fatalf("ResolveClaims (adopt by username): %v", err)
	}
	if resp.User.Id != created.ID.String() {
		t.Fatalf("expected adopted user ID %s, got %s", created.ID.String(), resp.User.Id)
	}
}

// TestResolveClaimsJITWhenNoLocalUserExists verifies the existing behaviour is
// unchanged when no pre-created local user exists for the token's hints.
func TestResolveClaimsJITWhenNoLocalUserExists(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := hinted(handlers.NewReadHandler(s))

	adoptCtx := incomingMDCtx(ctx, map[string]string{
		"x-identity-email": "brand.new@corp.example.com",
		"x-identity-name":  "Brand New",
	})

	resp, err := h.ResolveClaims(adoptCtx, &identityv1.ResolveClaimsRequest{
		ExternalSubject: "kc-brand-new-sub-999",
	})
	if err != nil {
		t.Fatalf("ResolveClaims (JIT): %v", err)
	}
	if resp.User == nil {
		t.Fatal("nil user")
	}
	if resp.User.Email != "brand.new@corp.example.com" {
		t.Fatalf("expected JIT email, got %q", resp.User.Email)
	}
}
