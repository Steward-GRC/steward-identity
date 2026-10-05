// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/polis"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// polisFake is an httptest stand-in for Polis's admin API used by the
// handler-level onboarding tests. It records the create form and delete query
// so the test can assert the wire contract, and lets a test force a create
// failure to exercise the compensating rollback.
type polisFake struct {
	srv *httptest.Server

	createForm  map[string]string
	deleteQuery map[string]string
	failCreate  bool
}

func newPolisFake(t *testing.T) *polisFake {
	t.Helper()
	f := &polisFake{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sso", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(body))
			f.createForm = flatten(vals)
			if f.failCreate {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":{"message":"polis rejected metadata"}}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"clientID":"CID-abc","clientSecret":"CSEC-xyz"}`)
		case http.MethodDelete:
			f.deleteQuery = flatten(r.URL.Query())
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func flatten(v url.Values) map[string]string {
	out := map[string]string{}
	for k := range v {
		out[k] = v.Get(k)
	}
	return out
}

func (f *polisFake) provisioner() *polis.Client {
	return polis.New(polis.Config{
		BaseURL:        f.srv.URL,
		APIKey:         "handler-test-key",
		Product:        "steward",
		GatewayBaseURL: "https://policies.example.org",
		HTTPClient:     f.srv.Client(),
	})
}

// TestAddOrganization_PolisSAML_ProvisionsAndActivates is the load-bearing
// re-point invariant: with the Polis provisioner selected, onboarding a SAML org
// POSTs a Polis connection (tenant=domain, product=policy, synthesized
// rawMetadata), persists the returned clientID (never the secret — #47) for
// teardown, and
// the EXISTING verify + test + activate gates still drive the connection live.
func TestAddOrganization_PolisSAML_ProvisionsAndActivates(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth())

	const cert = "-----BEGIN CERTIFICATE-----\nMIIDbodyABC\n-----END CERTIFICATE-----"
	resp, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName:     "Partner Organisation",
		Domain:      "partner.example.net", // mixed case → tenant must be lowercased
		Protocol:    "saml",
		DisplayName: "Partner Organisation SSO",
		Config: map[string]string{
			"entityId":               "https://idp.example.net/o/saml2?idpid=C01",
			"singleSignOnServiceUrl": "https://idp.example.net/o/saml2/idp?idpid=C01",
			"signingCertificate":     cert,
		},
	})
	require.NoError(t, err)
	org := resp.GetOrganization()
	require.NotNil(t, org)
	require.False(t, org.GetEnabled(), "connection must be created disabled")

	// Polis received the create with the locked tenant/product convention +
	// synthesized rawMetadata.
	require.Equal(t, "partner.example.net", f.createForm["tenant"])
	require.Equal(t, "steward", f.createForm["product"])
	require.Contains(t, f.createForm["rawMetadata"], "https://idp.example.net/o/saml2?idpid=C01")
	require.Contains(t, f.createForm["rawMetadata"], "MIIDbodyABC")
	require.NotContains(t, f.createForm["rawMetadata"], "BEGIN CERTIFICATE")

	// The Polis clientID + tenant/product were persisted on the connection's
	// config for later teardown. The clientSecret was NOT.
	conn, gerr := s.GetIdPConnectionByAlias(context.Background(), org.GetConnectionAlias())
	require.NoError(t, gerr)
	require.Equal(t, "CID-abc", conn.Config[polis.ConfigKeyPolisClientID])
	//: the client SECRET is deliberately NOT here. config is a
	// plaintext JSONB column, so the secret now lives in the out-of-band store
	// and only a reference is persisted. This handler was built without a
	// secret store (WithPolisSecrets unset), so there is no reference either
	// and teardown addresses the connection by tenant/product. The dedicated
	// coverage lives in admin_sso_polis_secret_test.go.
	_, secretInConfig := conn.Config["polisClientSecret"]
	require.False(t, secretInConfig, "the plaintext client secret must never be persisted on config")
	require.Equal(t, "partner.example.net", conn.Config[polis.ConfigKeyPolisTenant])
	require.Equal(t, "steward", conn.Config[polis.ConfigKeyPolisProduct])
	// The original wizard config is still present.
	require.Equal(t, "https://idp.example.net/o/saml2?idpid=C01", conn.Config["entityId"])

	// Drive the existing activation gates: domain verify + admin test → activate.
	start, err := h.StartDomainVerification(adminCtx(uuid.NewString()),
		&identityv1.StartDomainVerificationRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	token := start.GetToken()
	h.SetTXTLookup(func(_ context.Context, _ string) ([]string, error) {
		return []string{"steward-verify=" + token}, nil
	})
	vres, err := h.VerifyDomain(adminCtx(uuid.NewString()), &identityv1.VerifyDomainRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	require.True(t, vres.GetVerified())

	_, err = h.RecordIdPTestResult(adminCtx(uuid.NewString()), &identityv1.RecordIdPTestResultRequest{
		ConnectionId: org.GetConnectionId(), Success: true,
	})
	require.NoError(t, err)

	act, err := h.ActivateOrganization(adminCtx(uuid.NewString()),
		&identityv1.ActivateOrganizationRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	require.True(t, act.GetOrganization().GetEnabled(), "both gates satisfied → activated")

	// It now routes to sso.
	dm, derr := s.DiscoverMethod(context.Background(), "partner.example.net")
	require.NoError(t, derr)
	require.Equal(t, "sso", dm.Method)

	// Teardown: disable then delete must delete the Polis connection.
	//
	//: this handler has no secret store wired, so no client secret
	// was kept anywhere and the delete is addressed by tenant/product — the
	// pair Polis accepts and which is always populated. The clientSecret is
	// deliberately absent rather than read back from plaintext config. The
	// resolve-from-store path is covered by
	// TestDeleteOrganization_ResolvesPolisSecretAtUseTime.
	_, err = h.DisableOrganization(adminCtx(uuid.NewString()),
		&identityv1.DisableOrganizationRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	_, err = h.DeleteOrganization(adminCtx(uuid.NewString()),
		&identityv1.DeleteOrganizationRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	require.Equal(t, "CID-abc", f.deleteQuery["clientID"])
	require.Empty(t, f.deleteQuery["clientSecret"],
		"no client secret is stored, so none may be sent")
	require.Equal(t, "partner.example.net", f.deleteQuery["tenant"])
	require.Equal(t, "steward", f.deleteQuery["product"])

	// The connection row is gone.
	_, gerr = s.GetIdPConnectionByAlias(context.Background(), org.GetConnectionAlias())
	require.ErrorIs(t, gerr, store.ErrNotFound)
}

// TestAddOrganization_PolisFailureDoesNotHalfCreate: a Polis create failure
// must run the compensating DB delete and register NO domain — exactly the
// The same invariant through the Polis backend.
func TestAddOrganization_PolisFailureDoesNotHalfCreate(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	f.failCreate = true
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth())

	_, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName:  "BrokenCo",
		Domain:   "brokenco.example.net",
		Protocol: "saml",
		Config: map[string]string{
			"entityId":               "https://idp.broken.example.net",
			"singleSignOnServiceUrl": "https://idp.broken.example.net/sso",
			"signingCertificate":     "AAAAbase64",
		},
	})
	require.Equal(t, codes.Unavailable, status.Code(err), "polis failure → Unavailable")

	// No sso routing, and the compensating delete removed the row.
	res, derr := s.DiscoverMethod(context.Background(), "brokenco.example.net")
	if derr == nil {
		require.NotEqual(t, "sso", res.Method, "must never route to sso after a failed provision")
	}
	_, gerr := s.GetIdPConnectionByAlias(context.Background(), "brokenco")
	require.ErrorIs(t, gerr, store.ErrNotFound, "compensating delete must remove the half-created row")
}

// TestChangeOrgProtocol_PolisRecreatesByTenantAndClientID: a protocol change on
// a Polis org deletes the old Polis connection by the clientID and
// tenant/product persisted at onboarding, creates the new one under the same
// tenant, and keeps the routing alias the gateway and ResolveClaims key on.
func TestChangeOrgProtocol_PolisRecreatesByTenantAndClientID(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth())

	added, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName:  "SwitchCo",
		Domain:   "switchco.example.net",
		Protocol: "saml",
		Config: map[string]string{
			"entityId":               "https://idp.switch.example.net",
			"singleSignOnServiceUrl": "https://idp.switch.example.net/sso",
			"signingCertificate":     "AAAAbase64",
		},
	})
	require.NoError(t, err)
	alias := added.GetOrganization().GetConnectionAlias()
	require.NotEmpty(t, alias)

	resp, err := h.ChangeOrgProtocol(adminCtx(uuid.NewString()), &identityv1.ChangeOrgProtocolRequest{
		Domain:    "switchco.example.net",
		Protocol:  "oidc",
		Config:    map[string]string{"issuer": "https://idp.switch.example.net", "clientId": "policy"},
		SecretRef: "sso/switchco/oidc-secret",
	})
	require.NoError(t, err)

	require.Equal(t, "CID-abc", f.deleteQuery["clientID"])
	require.Equal(t, "switchco.example.net", f.deleteQuery["tenant"])
	require.Equal(t, "steward", f.deleteQuery["product"])

	require.Equal(t, "switchco.example.net", f.createForm["tenant"])
	require.Equal(t, "https://idp.switch.example.net", f.createForm["oidcDiscoveryUrl"])
	require.Equal(t, "policy", f.createForm["oidcClientId"])

	org := resp.GetOrganization()
	require.Equal(t, "oidc", org.GetProtocol())
	require.Equal(t, alias, org.GetConnectionAlias(), "the routing alias survives a protocol change")

	conn, err := s.GetIdPConnectionByAlias(context.Background(), alias)
	require.NoError(t, err)
	require.Equal(t, "CID-abc", conn.Config[polis.ConfigKeyPolisClientID])
	require.Equal(t, "switchco.example.net", conn.Config[polis.ConfigKeyPolisTenant])
}
