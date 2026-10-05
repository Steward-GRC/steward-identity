// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

func TestReadGetUser(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.JITProvision(context.Background(), "kc-gu", "gu@e", "Gu")
	h := handlers.NewReadHandler(s)
	resp, err := h.GetUser(context.Background(), &identityv1.GetUserRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if resp.User.Email != "gu@e" {
		t.Fatalf("email: %q", resp.User.Email)
	}
}

// TestReadGetUserByEmail covers the gateway's Kratos local-login resolution
// path: an exact, case-insensitive email
// match resolves the same platform user ResolveClaims would via
// external_subject.
func TestReadGetUserByEmail(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.JITProvision(context.Background(), "kc-gube", "GUBE@Example.com", "Gube")
	h := handlers.NewReadHandler(s)
	resp, err := h.GetUserByEmail(context.Background(), &identityv1.GetUserByEmailRequest{Email: "gube@example.com"})
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if resp.User.Id != u.ID.String() {
		t.Fatalf("id: got %q, want %q", resp.User.Id, u.ID.String())
	}
}

// TestReadGetUserByEmailNotFound covers the case the gateway maps to its
// 1215 coded login failure: a Kratos-authenticated email with no matching
// platform user.
func TestReadGetUserByEmailNotFound(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewReadHandler(s)
	_, err := h.GetUserByEmail(context.Background(), &identityv1.GetUserByEmailRequest{Email: "nobody@example.com"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestReadListUsersInGroup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, _ := s.JITProvision(ctx, "kc-lu", "lu@e", "Lu")
	g, _ := s.CreateGroup(ctx, "Team", uuid.Nil, nil, nil, "t")
	if _, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "t", "manual"); err != nil {
		t.Fatal(err)
	}
	h := handlers.NewReadHandler(s)
	resp, err := h.ListUsersInGroup(ctx, &identityv1.ListUsersInGroupRequest{GroupId: g.ID.String()})
	if err != nil {
		t.Fatalf("ListUsersInGroup: %v", err)
	}
	if len(resp.Users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(resp.Users))
	}
}

func TestReadListGroupDescendantsAncestors(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	root, _ := s.CreateGroup(ctx, "root", uuid.Nil, nil, nil, "t")
	child, _ := s.CreateGroup(ctx, "child", root.ID, nil, nil, "t")
	leaf, _ := s.CreateGroup(ctx, "leaf", child.ID, nil, nil, "t")

	h := handlers.NewReadHandler(s)
	d, err := h.ListGroupDescendants(ctx, &identityv1.ListGroupDescendantsRequest{GroupId: root.ID.String()})
	if err != nil {
		t.Fatalf("ListGroupDescendants: %v", err)
	}
	if len(d.Groups) != 2 {
		t.Fatalf("expected 2 descendants, got %d", len(d.Groups))
	}
	a, err := h.ListGroupAncestors(ctx, &identityv1.ListGroupAncestorsRequest{GroupId: leaf.ID.String()})
	if err != nil {
		t.Fatalf("ListGroupAncestors: %v", err)
	}
	if len(a.Groups) != 2 {
		t.Fatalf("expected 2 ancestors, got %d", len(a.Groups))
	}
}

func TestReadResolveFCMToken(t *testing.T) {
	s := newTestStore(t)
	u, _ := s.JITProvision(context.Background(), "kc-fcm", "fcm@e", "Fcm")
	h := handlers.NewReadHandler(s)
	resp, err := h.ResolveFCMToken(context.Background(), &identityv1.ResolveFCMTokenRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ResolveFCMToken: %v", err)
	}
	if resp.FcmToken != "" {
		t.Fatalf("expected empty fcm token by default, got %q", resp.FcmToken)
	}
}

func TestReadListUserGroups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	u, _ := s.JITProvision(ctx, "kc-lug", "lug@e", "Lug")
	g, _ := s.CreateGroup(ctx, "G", uuid.Nil, nil, nil, "t")
	if _, err := s.AddUserToGroup(ctx, u.ID, g.ID, nil, "t", "manual"); err != nil {
		t.Fatal(err)
	}
	h := handlers.NewReadHandler(s)
	resp, err := h.ListUserGroups(ctx, &identityv1.ListUserGroupsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserGroups: %v", err)
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(resp.Groups))
	}
}

func TestReadInputValidation(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewReadHandler(s)
	if _, err := h.GetUser(context.Background(), &identityv1.GetUserRequest{}); err == nil {
		t.Fatal("expected error for missing user_id")
	}
	if _, err := h.GetGroup(context.Background(), &identityv1.GetGroupRequest{GroupId: "not-uuid"}); err == nil {
		t.Fatal("expected error for malformed group_id")
	}
}

func TestAdminAuthorizeNoCreds(t *testing.T) {
	_ = newTestStore(t)
	auth := testAdminAuth()
	if _, err := auth.Authorize(context.Background()); err == nil {
		t.Fatal("expected PermissionDenied")
	}
}
