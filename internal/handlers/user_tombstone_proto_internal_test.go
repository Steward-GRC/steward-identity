// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestUserToProtoTombstoneFields pins the wire mapping of the
// tombstone fields. It needs no database: the defect it guards against is a
// silently unmapped field, which a DB-backed test on the live path would not
// catch because live rows have both fields empty anyway.
func TestUserToProtoTombstoneFields(t *testing.T) {
	deletedAt := time.Date(2026, 9, 15, 14, 47, 9, 0, time.UTC)
	target := uuid.New()
	source := uuid.New()

	t.Run("live account has both fields empty", func(t *testing.T) {
		got := userToProto(store.User{ID: source, Email: "live@x.example.org"})
		if got.GetDeletedAt() != "" {
			t.Errorf("deleted_at = %q, want empty for a live account", got.GetDeletedAt())
		}
		if got.GetMergedIntoUserId() != "" {
			t.Errorf("merged_into_user_id = %q, want empty for a live account", got.GetMergedIntoUserId())
		}
	})

	t.Run("deleted outright carries deleted_at only", func(t *testing.T) {
		got := userToProto(store.User{ID: source, Email: "dead@x.example.org", DeletedAt: &deletedAt})
		if want := "2026-09-15T14:47:09Z"; got.GetDeletedAt() != want {
			t.Errorf("deleted_at = %q, want RFC3339 %q", got.GetDeletedAt(), want)
		}
		if got.GetMergedIntoUserId() != "" {
			t.Errorf("merged_into_user_id = %q, want empty for a delete-outright tombstone", got.GetMergedIntoUserId())
		}
	})

	t.Run("merged away names the surviving account", func(t *testing.T) {
		got := userToProto(store.User{
			ID: source, Email: "merged@x.example.org",
			DeletedAt: &deletedAt, MergedIntoUserID: &target,
		})
		if got.GetDeletedAt() == "" {
			t.Errorf("a merged-away account must also carry deleted_at")
		}
		if got.GetMergedIntoUserId() != target.String() {
			t.Errorf("merged_into_user_id = %q, want the surviving account %s",
				got.GetMergedIntoUserId(), target)
		}
	})

	// A non-UTC stamp must still serialize as UTC RFC3339, or clients comparing
	// the string across services disagree about when the account closed.
	t.Run("non-UTC stamp normalises to UTC", func(t *testing.T) {
		loc := time.FixedZone("EST", -5*3600)
		local := deletedAt.In(loc)
		got := userToProto(store.User{ID: source, DeletedAt: &local})
		if want := "2026-09-15T14:47:09Z"; got.GetDeletedAt() != want {
			t.Errorf("deleted_at = %q, want %q", got.GetDeletedAt(), want)
		}
	})
}
