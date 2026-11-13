// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// A local account is created with one display name and no first or last name,
// so the typeahead has to match the stored display name too, or a person added
// that way can only be found by e-mail or username.
func TestSearchUsersMatchesTheStoredDisplayName(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()
	fiona, err := s.PreCreateLocalUser(ctx, "fiona.l", "f.l@namecol.example.org", "Fiona Marlowe")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	other, err := s.PreCreateLocalUser(ctx, "gus.k", "g.k@namecol.example.org", "Gustav Kline")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	for _, q := range []string{"fiona", "MARLOWE", "fiona marlowe", "Na Mar", "ona"} {
		got, err := s.SearchUsers(ctx, store.UserSearchOpts{Substring: q, Limit: 50})
		if err != nil {
			t.Fatalf("search %q: %v", q, err)
		}
		if !containsUser(got, fiona.ID) {
			t.Errorf("search %q did not find the account named Fiona Marlowe", q)
		}
		if containsUser(got, other.ID) {
			t.Errorf("search %q returned an unrelated person", q)
		}
	}
	got, err := s.SearchUsers(ctx, store.UserSearchOpts{Substring: "zzz-nobody", Limit: 50})
	if err != nil || len(got) != 0 {
		t.Fatalf("an unmatched query returned %d users (%v)", len(got), err)
	}
}
