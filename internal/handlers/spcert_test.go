// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/spkeys"
)

func spSeedSecret(ns, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       map[string][]byte{},
	}
}

func newSPKeys() spkeys.Store {
	return spkeys.NewK8sStore(
		fake.NewSimpleClientset(spSeedSecret("id-ns", "identity-sp-cert")),
		"id-ns", "identity-sp-cert")
}

// TestForceRotate_GracefulOverlap: rotation mints a new active cert, keeps the
// old row for the overlap window, and stores the new private key in the Secret
// (never the DB).
func TestForceRotate_GracefulOverlap(t *testing.T) {
	s := newTestStore(t)
	keys := newSPKeys()
	svc := handlers.NewSPCertService(keys, s, 365*24*time.Hour, 48*time.Hour)
	ctx := context.Background()

	require.NoError(t, svc.EnsureInitial(ctx))
	first, err := s.GetActiveSPCertificate(ctx)
	require.NoError(t, err)

	next, err := svc.ForceRotate(ctx)
	require.NoError(t, err)
	require.NotEqual(t, first.Serial, next.Serial)

	all, err := s.ListSPCertificates(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2, "old cert retained for overlap window")
	require.True(t, next.Active)

	pk, err := keys.GetKey(ctx, next.Serial)
	require.NoError(t, err)
	require.NotEmpty(t, pk, "private key persisted in k8s Secret, not DB")
}

// TestEnsureInitial_Idempotent: a second EnsureInitial does not regenerate.
func TestEnsureInitial_Idempotent(t *testing.T) {
	s := newTestStore(t)
	svc := handlers.NewSPCertService(newSPKeys(), s, 365*24*time.Hour, 48*time.Hour)
	ctx := context.Background()

	require.NoError(t, svc.EnsureInitial(ctx))
	first, err := s.GetActiveSPCertificate(ctx)
	require.NoError(t, err)

	require.NoError(t, svc.EnsureInitial(ctx))
	all, err := s.ListSPCertificates(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1, "second EnsureInitial must not regenerate")

	again, err := s.GetActiveSPCertificate(ctx)
	require.NoError(t, err)
	require.Equal(t, first.Serial, again.Serial)
}

// TestSPMetadataXML_BothDuringOverlap: metadata advertises a signing
// KeyDescriptor for BOTH the active and the overlapping cert, and never leaks
// the private key.
func TestSPMetadataXML_BothDuringOverlap(t *testing.T) {
	s := newTestStore(t)
	svc := handlers.NewSPCertService(newSPKeys(), s, 365*24*time.Hour, 48*time.Hour)
	ctx := context.Background()

	require.NoError(t, svc.EnsureInitial(ctx))
	_, err := svc.ForceRotate(ctx)
	require.NoError(t, err)

	xml, err := svc.SPMetadataXML(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, strings.Count(xml, "<KeyDescriptor"), "both active + overlapping certs advertised")
	require.Contains(t, xml, `use="signing"`)
	require.NotContains(t, xml, "PRIVATE KEY")
	require.NotContains(t, xml, "RSA PRIVATE KEY")
}

// TestPrivateKeyNeverInDB: the DB row holds only the public certificate; the
// private key lives solely in the k8s Secret.
func TestPrivateKeyNeverInDB(t *testing.T) {
	s := newTestStore(t)
	keys := newSPKeys()
	svc := handlers.NewSPCertService(keys, s, 365*24*time.Hour, 48*time.Hour)
	ctx := context.Background()

	require.NoError(t, svc.EnsureInitial(ctx))
	active, err := s.GetActiveSPCertificate(ctx)
	require.NoError(t, err)
	require.Contains(t, active.CertPEM, "CERTIFICATE")
	require.NotContains(t, active.CertPEM, "PRIVATE KEY")

	pk, err := keys.GetKey(ctx, active.Serial)
	require.NoError(t, err)
	require.Contains(t, string(pk), "PRIVATE KEY")
}
