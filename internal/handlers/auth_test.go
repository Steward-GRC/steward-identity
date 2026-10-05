// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"sync"
	"testing"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// testCLIID is the admin CLI identity the tests' AdminAuth admits.
const testCLIID = "spiffe://example.org/ns/steward/sa/identity-admin"

// roleRegistry stands in for the store's roles, so a test names its caller's
// roles the way the edge used to forward them.
type roleRegistry struct {
	mu sync.Mutex
	m  map[string][]string
}

func (r *roleRegistry) set(subject string, roles []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[subject] = append([]string(nil), roles...)
}

func (r *roleRegistry) UserRoles(_ context.Context, subject string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.m[subject], nil
}

var testRoles = &roleRegistry{m: map[string][]string{}}

// testAdminAuth admits the admin CLI and any caller whose test roles hold
// site-admin.
func testAdminAuth() *handlers.AdminAuth {
	return &handlers.AdminAuth{AdminCLIID: testCLIID, Roles: testRoles}
}

// claimsCtx returns a context carrying userID as the forwarded actor, with
// roles as that user's roles.
func claimsCtx(userID string, roles []string) context.Context {
	if userID == "" {
		return context.Background()
	}
	testRoles.set(userID, roles)
	return grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: userID})
}

// actingAsCtx returns a context in which admin acts as target.
func actingAsCtx(target, admin string) context.Context {
	return grpcactor.WithActor(context.Background(), grpcactor.Actor{Subject: target, Impersonator: admin})
}

func TestAuthorizeRequiresSiteAdminRole(t *testing.T) {
	auth := testAdminAuth()

	if _, err := auth.Authorize(claimsCtx("u-site", []string{"site-admin"})); err != nil {
		t.Fatalf("site-admin should authorize: %v", err)
	}
	// bare legacy "admin" (without site-admin) is NOT authorized anymore.
	if _, err := auth.Authorize(claimsCtx("u-legacy", []string{"admin"})); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("legacy admin must be denied, got %v", err)
	}
	// a non-admin role is denied.
	if _, err := auth.Authorize(claimsCtx("u-reader", []string{"author"})); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("author must be denied, got %v", err)
	}
}

func TestAuthorizeWithoutAnActorIsDenied(t *testing.T) {
	if _, err := testAdminAuth().Authorize(context.Background()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no actor must be denied, got %v", err)
	}
}

func TestAuthorizeChecksTheSubjectNotTheImpersonator(t *testing.T) {
	testRoles.set("u-erin", []string{"author"})
	testRoles.set("u-alice", []string{"site-admin"})
	if _, err := testAdminAuth().Authorize(actingAsCtx("u-erin", "u-alice")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("acting as a non-admin runs with the non-admin's rights, got %v", err)
	}
}
