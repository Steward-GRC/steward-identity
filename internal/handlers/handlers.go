// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package handlers implements identity's gRPC services: read, admin and SSO
// admin. Handlers translate between proto messages and store operations;
// authorization and audit live in helpers so each RPC stays short.
package handlers

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// statusFromStoreErr maps store sentinel errors to gRPC status codes.
func statusFromStoreErr(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, store.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, store.ErrConflict):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, store.ErrHasChildren),
		errors.Is(err, store.ErrHasMembers):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, store.ErrCycle):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, store.ErrRootProtected):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, store.ErrEmailMismatch):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, store.ErrSyncOwned):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

// userToProto translates a store.User into the wire-form User message.
func userToProto(u store.User) *identityv1.User {
	toStr := func(ids []uuid.UUID) []string {
		out := make([]string, len(ids))
		for i, g := range ids {
			out[i] = g.String()
		}
		return out
	}
	scoped := make([]*identityv1.ScopedRole, len(u.ScopedRoles))
	for i, sr := range u.ScopedRoles {
		scoped[i] = &identityv1.ScopedRole{Role: sr.Role, Category: sr.Category}
	}
	ovs := make([]*identityv1.PolicyOverride, len(u.PolicyOverrides))
	for i, p := range u.PolicyOverrides {
		ovs[i] = &identityv1.PolicyOverride{PolicyNumber: p.PolicyNumber, Effect: effectToProto(p.Effect)}
	}
	// Tombstone fields. Empty for a live account, which is every
	// row on the SEARCH path unless the caller opted into include_deleted, and
	// most rows on the RESOLVE path. They are populated on the resolve path too:
	// resolveUserLabels deliberately still returns tombstoned users so audit
	// history renders names, and without these a client on that path had no way
	// to render a closed account as closed.
	deletedAt := ""
	if u.DeletedAt != nil {
		deletedAt = u.DeletedAt.UTC().Format(time.RFC3339)
	}
	mergedInto := ""
	if u.MergedIntoUserID != nil {
		mergedInto = u.MergedIntoUserID.String()
	}
	return &identityv1.User{
		Id:                 u.ID.String(),
		Email:              u.Email,
		Name:               u.Name,
		FirstName:          u.FirstName,
		LastName:           u.LastName,
		Timezone:           u.Timezone,
		Locale:             u.Locale,
		Roles:              append([]string{}, u.Roles...),
		Groups:             toStr(u.Groups),
		Enabled:            u.Enabled,
		IsRoot:             u.IsRoot,
		ScopedRoles:        scoped,
		IdpGroups:          append([]string{}, u.IdpGroups...),
		PolicyOverrides:    ovs,
		ReadSensitiveGrant: u.ReadSensitive,
		LocalAccount:       u.LocalAccount,
		Username:           u.Username,
		NeedsOnboarding:    !u.OnboardingComplete,
		ManagedGroupIds:    toStr(u.ManagedGroups),
		Memberships:        membershipsToProto(u.Memberships),
		DeletedAt:          deletedAt,
		MergedIntoUserId:   mergedInto,
	}
}

// membershipsToProto translates store membership provenance rows into the
// wire-form Membership list.
func membershipsToProto(ms []store.Membership) []*identityv1.Membership {
	out := make([]*identityv1.Membership, len(ms))
	for i, m := range ms {
		out[i] = &identityv1.Membership{GroupId: m.GroupID.String(), Source: m.Source}
	}
	return out
}

// effectToProto converts a store effect string to the proto enum.
func effectToProto(e string) identityv1.OverrideEffect {
	switch e {
	case "allow":
		return identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW
	case "deny":
		return identityv1.OverrideEffect_OVERRIDE_EFFECT_DENY
	default:
		return identityv1.OverrideEffect_OVERRIDE_EFFECT_UNSPECIFIED
	}
}

// effectFromProto converts the proto enum to a store effect string.
func effectFromProto(e identityv1.OverrideEffect) string {
	switch e {
	case identityv1.OverrideEffect_OVERRIDE_EFFECT_ALLOW:
		return "allow"
	case identityv1.OverrideEffect_OVERRIDE_EFFECT_DENY:
		return "deny"
	default:
		return ""
	}
}

// groupToProto translates a store.Group into the wire-form Group message.
func groupToProto(g store.Group) *identityv1.Group {
	meta := g.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	parent := ""
	if g.ParentID != uuid.Nil {
		parent = g.ParentID.String()
	}
	return &identityv1.Group{
		Id:       g.ID.String(),
		Name:     g.Name,
		ParentId: parent,
		Metadata: meta,
	}
}

// parseUUID returns a friendly InvalidArgument status on parse failure.
func parseUUID(s, field string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "%s required", field)
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "invalid %s: %v", field, err)
	}
	return id, nil
}

// parseOptionalUUID accepts the empty string (returning uuid.Nil) but
// reports parse errors for non-empty malformed values.
func parseOptionalUUID(s, field string) (uuid.UUID, error) {
	if s == "" {
		return uuid.Nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.InvalidArgument, "invalid %s: %v", field, err)
	}
	return id, nil
}
