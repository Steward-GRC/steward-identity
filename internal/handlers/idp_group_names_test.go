// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

func seedUserIdpGroups(t *testing.T, s *store.Store, subject string, names []string) {
	t.Helper()
	ctx := context.Background()
	u, err := s.JITProvision(ctx, "sub-"+subject, subject+"@idpn.example.org", subject)
	require.NoError(t, err)
	require.NoError(t, s.ReplaceUserIdpGroups(ctx, u.ID, names))
}

func TestListIdpGroupNames_DistinctSortedAndPrefixed(t *testing.T) {
	s := newTestStore(t)
	seedUserIdpGroups(t, s, "one", []string{"Finance", "eng"})
	seedUserIdpGroups(t, s, "two", []string{"Finance", "finops"})
	h := handlers.NewReadHandler(s)
	ctx := context.Background()

	resp, err := h.ListIdpGroupNames(ctx, &identityv1.ListIdpGroupNamesRequest{})
	require.NoError(t, err)
	require.Equal(t, []string{"Finance", "eng", "finops"}, resp.GetNames())
	require.False(t, resp.GetTruncated())

	resp, err = h.ListIdpGroupNames(ctx, &identityv1.ListIdpGroupNamesRequest{Prefix: "  FIN "})
	require.NoError(t, err)
	require.Equal(t, []string{"Finance", "finops"}, resp.GetNames())
}

func TestListIdpGroupNames_LimitTruncatesAndDefaultsAndCaps(t *testing.T) {
	s := newTestStore(t)
	names := make([]string, 0, 260)
	for i := 0; i < 260; i++ {
		names = append(names, fmt.Sprintf("grp-%03d", i))
	}
	seedUserIdpGroups(t, s, "many", names)
	h := handlers.NewReadHandler(s)
	ctx := context.Background()

	resp, err := h.ListIdpGroupNames(ctx, &identityv1.ListIdpGroupNamesRequest{Limit: 2})
	require.NoError(t, err)
	require.Equal(t, []string{"grp-000", "grp-001"}, resp.GetNames())
	require.True(t, resp.GetTruncated())

	resp, err = h.ListIdpGroupNames(ctx, &identityv1.ListIdpGroupNamesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetNames(), 50, "unset limit is the default page")
	require.True(t, resp.GetTruncated())

	resp, err = h.ListIdpGroupNames(ctx, &identityv1.ListIdpGroupNamesRequest{Limit: 100000})
	require.NoError(t, err)
	require.Len(t, resp.GetNames(), 200, "an oversized limit is capped")
	require.True(t, resp.GetTruncated())

	resp, err = h.ListIdpGroupNames(ctx, &identityv1.ListIdpGroupNamesRequest{Prefix: "grp-25", Limit: 10})
	require.NoError(t, err)
	require.Len(t, resp.GetNames(), 10)
	require.False(t, resp.GetTruncated(), "exactly the limit is not truncated")
}

func TestListIdpGroupNames_RefusesAnOverlongPrefix(t *testing.T) {
	h := handlers.NewReadHandler(newTestStore(t))
	long := make([]byte, 257)
	for i := range long {
		long[i] = 'a'
	}
	_, err := h.ListIdpGroupNames(context.Background(), &identityv1.ListIdpGroupNamesRequest{Prefix: string(long)})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
