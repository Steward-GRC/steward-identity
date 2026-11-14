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

// seedIdpGroupNames gives two users overlapping IdP groups and maps two claim
// values on one connection, one of them also held by a user.
func seedIdpGroupNames(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	a, err := s.JITProvision(ctx, "sub-idpn-a", "a@idpn.example.org", "A")
	require.NoError(t, err)
	b, err := s.JITProvision(ctx, "sub-idpn-b", "b@idpn.example.org", "B")
	require.NoError(t, err)
	require.NoError(t, s.ReplaceUserIdpGroups(ctx, a.ID, []string{"Finance", "eng", "50%_off"}))
	require.NoError(t, s.ReplaceUserIdpGroups(ctx, b.ID, []string{"Finance", "finops"}))

	conn, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "Idpn Org", Protocol: "oidc", ConnectionAlias: "idpn-org"})
	require.NoError(t, err)
	g, err := s.CreateGroup(ctx, "Platform eng", uuid.Nil, nil, nil, "test")
	require.NoError(t, err)
	_, err = s.AddIdPGroupMapping(ctx, conn.ID, "eng", g.ID)
	require.NoError(t, err)
	_, err = s.AddIdPGroupMapping(ctx, conn.ID, "mapped-only", g.ID)
	require.NoError(t, err)
}

func TestListIdpGroupNames_DistinctSortedUnionOfUsersAndMappings(t *testing.T) {
	s := newTestStore(t)
	seedIdpGroupNames(t, s)

	got, err := s.ListIdpGroupNames(context.Background(), "", 50)
	require.NoError(t, err)
	// Distinct (Finance and eng are held or mapped more than once), byte order
	// (upper case before lower), with the mapped-only claim value included.
	require.Equal(t, []string{"50%_off", "Finance", "eng", "finops", "mapped-only"}, got)
}

func TestListIdpGroupNames_PrefixIsCaseInsensitiveAndWildcardsAreText(t *testing.T) {
	s := newTestStore(t)
	seedIdpGroupNames(t, s)
	ctx := context.Background()

	got, err := s.ListIdpGroupNames(ctx, "fin", 50)
	require.NoError(t, err)
	require.Equal(t, []string{"Finance", "finops"}, got)

	got, err = s.ListIdpGroupNames(ctx, "%", 50)
	require.NoError(t, err)
	require.Empty(t, got, "a percent sign is text, not a wildcard")

	got, err = s.ListIdpGroupNames(ctx, "50%_", 50)
	require.NoError(t, err)
	require.Equal(t, []string{"50%_off"}, got)

	got, err = s.ListIdpGroupNames(ctx, "nothing-like-this", 50)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, got)
}

func TestListIdpGroupNames_LimitCapsTheResult(t *testing.T) {
	s := newTestStore(t)
	seedIdpGroupNames(t, s)

	got, err := s.ListIdpGroupNames(context.Background(), "", 2)
	require.NoError(t, err)
	require.Equal(t, []string{"50%_off", "Finance"}, got)
}

func TestListIdpGroupNames_EmptyDirectory(t *testing.T) {
	s := newTestStore(t)
	got, err := s.ListIdpGroupNames(context.Background(), "", 50)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Empty(t, got)
}
