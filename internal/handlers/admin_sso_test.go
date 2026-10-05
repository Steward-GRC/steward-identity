// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestSSOAdmin_ProtoSymbolsExist checks the SSO admin proto types compile
// and are usable.
func TestSSOAdmin_ProtoSymbolsExist(t *testing.T) {
	_ = &identityv1.AddOrganizationRequest{OrgName: "x", Domain: "x.example.net", Protocol: "oidc"}
	_ = &identityv1.SPCertificate{Serial: "1"}
}

// ssoAdminAuth returns an AdminAuth wired for the role-based (gateway) path;
// paired with adminCtx it authorizes the RPC under test.
func ssoAdminAuth() *handlers.AdminAuth {
	return testAdminAuth()
}

// TestAddOrganization_HappyPath: backend provisioning succeeds → a disabled
// connection exists and the domain is registered as method=sso. It does NOT
// yet route to sso (unverified + disabled + no passed test), so DiscoverMethod
// falls back to local per the activation gating — that's expected and correct.
func TestAddOrganization_HappyPath(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth())

	resp, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName:     "Partner Organisation",
		Domain:      "partner.example.net",
		Protocol:    "oidc",
		DisplayName: "Partner Organisation SSO",
		Config:      map[string]string{"issuer": "https://idp.partner.example.net", "clientId": "policy"},
		SecretRef:   "sso/partner/oidc-secret",
	})
	if err != nil {
		t.Fatalf("AddOrganization: %v", err)
	}
	org := resp.GetOrganization()
	if org == nil {
		t.Fatal("expected non-nil organization")
	}
	if org.GetConnectionAlias() == "" {
		t.Fatal("expected a generated connection_alias")
	}
	if org.GetEnabled() {
		t.Fatal("connection must be created disabled")
	}
	if org.GetProtocol() != "oidc" {
		t.Fatalf("protocol: got %q", org.GetProtocol())
	}

	// The connection was provisioned in Polis under the org's domain tenant.
	if f.createForm["tenant"] != "partner.example.net" {
		t.Fatalf("expected a Polis connection for tenant partner.example.net, got %q", f.createForm["tenant"])
	}

	// The domain is registered as method=sso in the registry (even though it
	// doesn't route to sso yet — activation gates come later).
	d, gerr := s.GetSSODomain(context.Background(), "partner.example.net")
	if gerr != nil {
		t.Fatalf("GetSSODomain: %v", gerr)
	}
	if d.Method != "sso" {
		t.Fatalf("expected method=sso, got %q", d.Method)
	}
	if d.ConnectionID == nil {
		t.Fatal("expected connection_id set on the sso domain")
	}
}

// TestAddOrganization_RequiresAuth: unauthenticated callers are rejected before
// any DB or backend work.
func TestAddOrganization_RequiresAuth(t *testing.T) {
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth())
	_, err := h.AddOrganization(noopCtx(), &identityv1.AddOrganizationRequest{
		OrgName: "Partner Organisation", Domain: "partner.example.net", Protocol: "oidc",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}
