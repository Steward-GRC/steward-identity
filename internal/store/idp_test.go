// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestApplyIdPGroupMappings verifies that an asserted IdP group with a
// mapping to an existing target group is applied by id (AddUserToGroup) and
// an asserted IdP group with no mapping at all is simply ignored.
func TestApplyIdPGroupMappings(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org"})
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Approvers", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)
	_, err = s.AddIdPGroupMapping(ctx, conn.ID, "eng", g.ID)
	require.NoError(t, err)
	u, err := s.JITProvision(ctx, "sub-9", "x@example.org", "X")
	require.NoError(t, err)

	applied, skipped, err := s.ApplyIdPGroupMappings(ctx, u.ID, conn.ID, []string{"eng", "unmapped"})
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{g.ID}, applied)
	require.Empty(t, skipped)

	groups, err := s.ListUserGroups(ctx, u.ID, false)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, g.ID, groups[0].ID)
}

// TestApplyIdPGroupMappings_SameNameDifferentParent is the whole point of the
// id-based mapping: two groups share the display name "Approvers" under
// different parents. A name-based mapping could silently resolve to the wrong
// one; the id-based mapping must land the user in EXACTLY the mapped group and
// never the same-named sibling.
func TestApplyIdPGroupMappings_SameNameDifferentParent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org2"})
	require.NoError(t, err)

	exampleOrg, err := s.CreateGroup(ctx, "Example Organisation", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)
	partnerOrg, err := s.CreateGroup(ctx, "Partner Organisation", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)
	// Two DISTINCT groups both named "Approvers", one under each parent.
	exampleApprovers, err := s.CreateGroup(ctx, "Approvers", exampleOrg.ID, nil, nil, "test")
	require.NoError(t, err)
	partnerApprovers, err := s.CreateGroup(ctx, "Approvers", partnerOrg.ID, nil, nil, "test")
	require.NoError(t, err)
	require.NotEqual(t, exampleApprovers.ID, partnerApprovers.ID)

	// Map the asserted claim to the partner Approvers group specifically.
	_, err = s.AddIdPGroupMapping(ctx, conn.ID, "eng", partnerApprovers.ID)
	require.NoError(t, err)

	u, err := s.JITProvision(ctx, "sub-sn", "sn@example.org", "SN")
	require.NoError(t, err)

	applied, skipped, err := s.ApplyIdPGroupMappings(ctx, u.ID, conn.ID, []string{"eng"})
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{partnerApprovers.ID}, applied, "must grant the exact mapped group by id")
	require.Empty(t, skipped)

	groups, err := s.ListUserGroups(ctx, u.ID, false)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, partnerApprovers.ID, groups[0].ID, "granted the partner Approvers, never the same-named sibling")
}

// TestApplyIdPGroupMappings_DeletedTargetNeverFailsLogin proves that deleting a
// mapped target group can never break a subsequent SSO login. The FK's ON
// DELETE CASCADE removes the mapping row along with the group, so the asserted
// claim simply has no mapping left — login succeeds with no grant rather than
// erroring on a dangling id.
func TestApplyIdPGroupMappings_DeletedTargetNeverFailsLogin(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "oidc", ConnectionAlias: "example-org3"})
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Temp", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)
	_, err = s.AddIdPGroupMapping(ctx, conn.ID, "temp", g.ID)
	require.NoError(t, err)
	u, err := s.JITProvision(ctx, "sub-st", "st@example.org", "ST")
	require.NoError(t, err)

	// Deleting the group cascades away its mapping (FK ON DELETE CASCADE).
	require.NoError(t, s.DeleteGroup(ctx, g.ID, nil, "test"))
	list, err := s.ListIdPGroupMappings(ctx, conn.ID)
	require.NoError(t, err)
	require.Empty(t, list, "deleting the target group cascades the mapping away")

	applied, skipped, err := s.ApplyIdPGroupMappings(ctx, u.ID, conn.ID, []string{"temp"})
	require.NoError(t, err, "a removed target must never fail the login")
	require.Empty(t, applied)
	require.Empty(t, skipped)
}

// TestIdPGroupMappingCRUD covers Add/List/Delete on their own.
func TestIdPGroupMappingCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Example Organisation", Protocol: "saml", ConnectionAlias: "example-org-saml"})
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Approvers", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)

	m, err := s.AddIdPGroupMapping(ctx, conn.ID, "eng", g.ID)
	require.NoError(t, err)
	require.Equal(t, conn.ID, m.ConnectionID)
	require.Equal(t, "eng", m.IdPGroupClaimValue)
	require.Equal(t, g.ID, m.TargetGroupID)
	require.NotEqual(t, uuid.Nil, m.ID)

	list, err := s.ListIdPGroupMappings(ctx, conn.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, m.ID, list[0].ID)

	require.NoError(t, s.DeleteIdPGroupMapping(ctx, m.ID))

	list, err = s.ListIdPGroupMappings(ctx, conn.ID)
	require.NoError(t, err)
	require.Len(t, list, 0)
}

// TestDeleteIdPGroupMapping_NotFound verifies ErrNotFound on a missing id.
func TestDeleteIdPGroupMapping_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	err := s.DeleteIdPGroupMapping(ctx, uuid.New())
	require.ErrorIs(t, err, store.ErrNotFound)
}
