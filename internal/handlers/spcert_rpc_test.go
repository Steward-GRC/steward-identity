// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// newSSOAdminHandlerWithSPCert builds an SSOAdminHandler wired to a real
// spCertService — backed by the (testcontainers) store and a fake k8s Secret
// via newSPKeys (spcert_test.go) — with an active cert already seeded via
// EnsureInitial. Mirrors newTestStore's skip idiom: on a nil store the caller
// never reaches its next line (t.Skip unwinds the whole goroutine).
func newSSOAdminHandlerWithSPCert(t *testing.T) (*handlers.SSOAdminHandler, *store.Store) {
	t.Helper()
	s := newTestStore(t)
	if s == nil {
		return nil, nil
	}
	svc := handlers.NewSPCertService(newSPKeys(), s, 365*24*time.Hour, 48*time.Hour)
	require.NoError(t, svc.EnsureInitial(context.Background()))
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).WithSPCert(svc)
	return h, s
}

// TestGetSPCertificate_PublicOnly: GetSPCertificate never returns a private
// key field and returns SP metadata XML.
//
// NOTE: unlike the brief's idealized adminCtx(), this repo's adminCtx takes a
// userID (see admin_test.go) — adminCtx(uuid.NewString()) is the equivalent
// authorized context used by every other SSO admin test.
func TestGetSPCertificate_PublicOnly(t *testing.T) {
	h, _ := newSSOAdminHandlerWithSPCert(t)
	resp, err := h.GetSPCertificate(adminCtx(uuid.NewString()), &identityv1.GetSPCertificateRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetCertificate().GetCertPem())
	require.Contains(t, resp.GetCertificate().GetSpMetadataXml(), "<KeyDescriptor")
	// proto has no private-key field at all — compile-time guarantee
}

// TestGetSPCertificate_ReturnsActiveMetadata: the returned row matches the
// active cert in the store (serial + active flag).
func TestGetSPCertificate_ReturnsActiveMetadata(t *testing.T) {
	h, s := newSSOAdminHandlerWithSPCert(t)
	active, err := s.GetActiveSPCertificate(context.Background())
	require.NoError(t, err)

	resp, err := h.GetSPCertificate(adminCtx(uuid.NewString()), &identityv1.GetSPCertificateRequest{})
	require.NoError(t, err)
	require.Equal(t, active.Serial, resp.GetCertificate().GetSerial())
	require.True(t, resp.GetCertificate().GetActive())
	require.NotEmpty(t, resp.GetCertificate().GetNotAfter())
}

// TestListSPCertificates_PublicRowsNoKey: List returns every row, public
// fields only.
func TestListSPCertificates_PublicRowsNoKey(t *testing.T) {
	h, _ := newSSOAdminHandlerWithSPCert(t)
	resp, err := h.ListSPCertificates(adminCtx(uuid.NewString()), &identityv1.ListSPCertificatesRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetCertificates(), 1)
	c := resp.GetCertificates()[0]
	require.NotEmpty(t, c.GetCertPem())
	require.NotEmpty(t, c.GetSerial())
	require.True(t, c.GetActive())
}

// TestForceRotateSPCertificate_NewSerialAndEvent: rotating mints a new
// serial and publishes sso.sp_cert_rotated.
func TestForceRotateSPCertificate_NewSerialAndEvent(t *testing.T) {
	h, s := newSSOAdminHandlerWithSPCert(t)
	before, err := s.GetActiveSPCertificate(context.Background())
	require.NoError(t, err)

	pub := &fakeSSOEventPublisher{}
	h.WithSSOEventPublisher(pub)

	resp, err := h.ForceRotateSPCertificate(adminCtx(uuid.NewString()), &identityv1.ForceRotateSPCertificateRequest{})
	require.NoError(t, err)
	require.NotEqual(t, before.Serial, resp.GetCertificate().GetSerial())
	require.True(t, resp.GetCertificate().GetActive())

	require.Len(t, pub.calls, 1)
	require.Equal(t, "sso.sp_cert_rotated", pub.calls[0])
}

// TestSPCertRPCs_UnavailableWhenNotWired: without WithSPCert, all three RPCs
// return a clean Unavailable rather than panicking on a nil sp field.
func TestSPCertRPCs_UnavailableWhenNotWired(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	ctx := adminCtx(uuid.NewString())

	_, err := h.GetSPCertificate(ctx, &identityv1.GetSPCertificateRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))

	_, err = h.ListSPCertificates(ctx, &identityv1.ListSPCertificatesRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))

	_, err = h.ForceRotateSPCertificate(ctx, &identityv1.ForceRotateSPCertificateRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// TestSPCertRPCs_RequireAuth: each of the three RPCs is PermissionDenied
// without an authorized context — checked ahead of the nil-sp gate, so an
// unauthenticated caller can never probe whether SP-cert is enabled.
func TestSPCertRPCs_RequireAuth(t *testing.T) {
	h, _ := newSSOAdminHandlerWithSPCert(t)

	_, err := h.GetSPCertificate(noopCtx(), &identityv1.GetSPCertificateRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = h.ListSPCertificates(noopCtx(), &identityv1.ListSPCertificatesRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = h.ForceRotateSPCertificate(noopCtx(), &identityv1.ForceRotateSPCertificateRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// fakeSSOEventPublisher records the lifecycle event names published to it via
// the PublishSSO seam.
type fakeSSOEventPublisher struct {
	calls []string
}

func (f *fakeSSOEventPublisher) PublishSSO(_ context.Context, event string, _ map[string]any) error {
	f.calls = append(f.calls, event)
	return nil
}
