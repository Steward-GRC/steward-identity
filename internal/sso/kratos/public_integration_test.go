//go:build integration

// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package kratos_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

// TestPublicChangePasswordAgainstKratos runs the change against a real Kratos
// with a throwaway account that it creates and deletes. It needs
// KRATOS_PUBLIC_URL and KRATOS_ADMIN_URL (the local harness forwards 4433 and
// 4434). The passwords are random and never printed.
func TestPublicChangePasswordAgainstKratos(t *testing.T) {
	pub, adm := os.Getenv("KRATOS_PUBLIC_URL"), os.Getenv("KRATOS_ADMIN_URL")
	if pub == "" || adm == "" {
		t.Skip("KRATOS_PUBLIC_URL and KRATOS_ADMIN_URL are not set")
	}
	admin := kratos.New(adm, 10*time.Second)
	public := kratos.NewPublic(pub, 10*time.Second)
	suffix := uuid.NewString()
	email := "pwchange-" + suffix[:8] + "@example.invalid"
	current := "cur-" + uuid.NewString()
	id, err := admin.CreateIdentity(t.Context(), kratos.Account{Username: "pwchange" + suffix[:8], Email: email, Name: "Throwaway"}, current)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.DeleteIdentity(context.Background(), id)) })

	require.ErrorIs(t, public.ChangePassword(t.Context(), email, "not-"+current, "new-"+uuid.NewString()), kratos.ErrWrongPassword)
	require.ErrorIs(t, public.ChangePassword(t.Context(), email, current, "short"), kratos.ErrWeakPassword)

	next := "new-" + uuid.NewString()
	require.NoError(t, public.ChangePassword(t.Context(), email, current, next))
	require.ErrorIs(t, public.ChangePassword(t.Context(), email, current, "other-"+uuid.NewString()), kratos.ErrWrongPassword, "the old password no longer works")
	require.NoError(t, public.ChangePassword(t.Context(), email, next, "last-"+uuid.NewString()), "the new password does")

	sessions, err := admin.ListSessions(t.Context(), id)
	require.NoError(t, err)
	for _, s := range sessions {
		require.False(t, s.Active, "the checks leave no active session behind")
	}
}
