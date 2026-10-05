// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// TestSPCertificateLifecycle exercises the sp_certificates repo end to end
// against a migrated database: insert active, add an inactive successor, flip
// the active pointer, schedule the predecessor's retirement, and confirm the
// single-active partial unique index rejects a second active row.
func TestSPCertificateLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.GetActiveSPCertificate(ctx)
	require.ErrorIs(t, err, store.ErrNotFound)

	c1 := store.SPCertificate{ID: uuid.New(), Serial: "111", CertPEM: "PUB-1", SecretRef: "111", Active: true, NotAfter: time.Now().Add(24 * time.Hour)}
	require.NoError(t, s.InsertSPCertificate(ctx, c1))

	got, err := s.GetActiveSPCertificate(ctx)
	require.NoError(t, err)
	require.Equal(t, "111", got.Serial)
	require.Nil(t, got.RetiredAt)

	c2 := store.SPCertificate{ID: uuid.New(), Serial: "222", CertPEM: "PUB-2", SecretRef: "222", Active: false, NotAfter: time.Now().Add(24 * time.Hour)}
	require.NoError(t, s.InsertSPCertificate(ctx, c2))

	require.NoError(t, s.SetActiveSPCertificate(ctx, c2.ID))
	got, err = s.GetActiveSPCertificate(ctx)
	require.NoError(t, err)
	require.Equal(t, "222", got.Serial)

	n, err := s.RetireOldSPCertificates(ctx, c2.ID, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, n)

	all, err := s.ListSPCertificates(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	for _, c := range all {
		switch c.Serial {
		case "111":
			require.NotNil(t, c.RetiredAt, "rotated-out cert is scheduled to retire")
		case "222":
			require.Nil(t, c.RetiredAt, "active cert is not retired")
		}
	}

	// The single-active partial unique index must reject a second active row.
	c3 := store.SPCertificate{ID: uuid.New(), Serial: "333", CertPEM: "PUB-3", SecretRef: "333", Active: true, NotAfter: time.Now().Add(24 * time.Hour)}
	require.Error(t, s.InsertSPCertificate(ctx, c3))
}

// TestSetActiveSPCertificateUnknown returns ErrNotFound for a missing id.
func TestSetActiveSPCertificateUnknown(t *testing.T) {
	s := newTestStore(t)
	require.ErrorIs(t, s.SetActiveSPCertificate(context.Background(), uuid.New()), store.ErrNotFound)
}
