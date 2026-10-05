// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// capturePublisher records every routing key it is asked to publish so a test
// can assert that DeleteUser emits membership.changed for the deleted user.
type capturePublisher struct {
	mu   sync.Mutex
	keys []string
	body [][]byte
}

func (c *capturePublisher) Publish(_ context.Context, routingKey string, body []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = append(c.keys, routingKey)
	c.body = append(c.body, body)
	return nil
}

func (c *capturePublisher) has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.keys, key)
}

func (c *capturePublisher) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.keys...)
}

// TestDeleteUserSoftDeletesRevokesAndEmits verifies the happy path: the account
// is disabled (soft-delete), its active session is revoked and counted, its
// group membership is stripped, and a membership.changed event is emitted so
// downstream ack obligations can be reconciled. It must NOT error — identity
// holds no policies to worry about.
//
// added two MANDATORY pre-delete steps (outstanding-approval check
// + credential revoke), so the handler is now built with both seams wired. The
// assertions below are unchanged: an account with no pending approvals and a
// revocable credential still deletes, and re-deletes, exactly as before.
func TestDeleteUserSoftDeletesRevokesAndEmits(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-del-admin", "admin@e", "Admin")
	target, _ := s.JITProvision(ctx, "kc-del-target", "target@e", "Target")
	fk := newFakeKratos()
	fk.addWithID("kc-del-target", kratos.Account{Email: "target@e", Name: "Target"})
	fk.addSession("kc-del-target", true)

	pub := &capturePublisher{}
	h := deleteHandler(s, &fakeApprovals{}, &fakeRevoker{res: revokedOK("kratos-del-target")}).
		WithCredentialRevoker(fk).WithSignIn(fk).WithMembershipPublisher(pub)

	// Give the target a group membership so we can prove access rows are dropped.
	g, err := h.CreateGroup(adminCtx(admin.ID.String()), &identityv1.CreateGroupRequest{Name: "Team-Del"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := h.AddUserToGroup(adminCtx(admin.ID.String()), &identityv1.AddUserToGroupRequest{
		UserId: target.ID.String(), GroupId: g.Group.Id,
	}); err != nil {
		t.Fatalf("AddUserToGroup: %v", err)
	}

	resp, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if resp.GetUser().GetEnabled() {
		t.Fatal("deleted user must be disabled")
	}
	if resp.GetRevokedSessions() != 1 {
		t.Fatalf("revoked sessions: got %d, want 1", resp.GetRevokedSessions())
	}

	// Group membership must be gone (access rows dropped).
	groups, err := s.ListUserGroups(ctx, target.ID, false)
	if err != nil {
		t.Fatalf("ListUserGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("deleted user still in %d group(s)", len(groups))
	}

	// A membership.changed event must have been emitted for the deleted user.
	if !pub.has("membership.changed") {
		t.Fatalf("expected a membership.changed event, got keys %v", pub.snapshot())
	}

	// Idempotent: a second delete revokes nothing and still succeeds.
	resp2, err := h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: target.ID.String()})
	if err != nil {
		t.Fatalf("DeleteUser (repeat): %v", err)
	}
	if resp2.GetRevokedSessions() != 0 {
		t.Fatalf("repeat delete revoked %d sessions, want 0", resp2.GetRevokedSessions())
	}
}

// TestDeleteUserRootProtected proves the root account cannot be deleted.
func TestDeleteUserRootProtected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	admin, _ := s.JITProvision(ctx, "kc-del-a2", "a2@e", "A2")
	root, err := s.PreCreateLocalUserRoot(ctx, "root-del", "root-del@e", "Root")
	if err != nil {
		t.Fatalf("PreCreateLocalUserRoot: %v", err)
	}
	h := handlers.NewAdminHandler(s, testAdminAuth())

	_, err = h.DeleteUser(adminCtx(admin.ID.String()), &identityv1.DeleteUserRequest{UserId: root.ID.String()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("delete root: got %v, want FailedPrecondition", err)
	}
}

// TestDeleteUserNotFound proves an unknown user yields NotFound.
func TestDeleteUserNotFound(t *testing.T) {
	s := newTestStore(t)
	admin, _ := s.JITProvision(context.Background(), "kc-del-a3", "a3@e", "A3")
	h := handlers.NewAdminHandler(s, testAdminAuth())

	_, err := h.DeleteUser(adminCtx(admin.ID.String()),
		&identityv1.DeleteUserRequest{UserId: "00000000-0000-0000-0000-000000000000"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("delete missing user: got %v, want NotFound", err)
	}
}
