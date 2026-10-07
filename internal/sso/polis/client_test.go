// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package polis

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakePolis is an httptest-backed stand-in for Polis's admin API. It records
// the last create request so tests can assert the wire contract.
type fakePolis struct {
	srv *httptest.Server

	gotAuth        string
	gotContentType string
	gotForm        map[string]string
	gotDeleteQuery map[string]string
	gotPatchForm   map[string]string
	patchStatus    int

	createStatus int    // status to return on POST (default 200)
	createBody   string // body to return on POST (default a clientID/clientSecret JSON)
}

func newFakePolis(t *testing.T) *fakePolis {
	t.Helper()
	f := &fakePolis{createStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sso", func(w http.ResponseWriter, r *http.Request) {
		f.gotAuth = r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodPost:
			f.gotContentType = r.Header.Get("Content-Type")
			body, _ := io.ReadAll(r.Body)
			vals, _ := parseForm(string(body))
			f.gotForm = vals
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.createStatus)
			if f.createBody != "" {
				_, _ = io.WriteString(w, f.createBody)
			} else {
				_, _ = io.WriteString(w, `{"clientID":"cid-123","clientSecret":"csec-456","name":"n"}`)
			}
		case http.MethodPatch:
			f.gotContentType = r.Header.Get("Content-Type")
			body, _ := io.ReadAll(r.Body)
			f.gotPatchForm, _ = parseForm(string(body))
			if f.patchStatus != 0 {
				w.WriteHeader(f.patchStatus)
				_, _ = io.WriteString(w, `{"error":{"message":"clientSecret mismatch"}}`)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			q := map[string]string{}
			for k := range r.URL.Query() {
				q[k] = r.URL.Query().Get(k)
			}
			f.gotDeleteQuery = q
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

// parseForm is a tiny url-encoded body parser kept local so the test asserts on
// the exact fields the provisioner sends.
func parseForm(body string) (map[string]string, error) {
	out := map[string]string{}
	vals, err := url.ParseQuery(body)
	if err != nil {
		return nil, err
	}
	for k, v := range vals {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out, nil
}

func newTestPolis(t *testing.T, f *fakePolis) *Client {
	t.Helper()
	return New(Config{
		BaseURL:        f.srv.URL,
		APIKey:         "test-key",
		Product:        "steward",
		GatewayBaseURL: "https://policies.example.org",
		HTTPClient:     f.srv.Client(),
	})
}

// TestPolisCreateConnection_SAML asserts the create call posts the locked
// tenant=domain / product=steward convention, an Api-Key auth header, a redirect
// allowlist off the gateway base, and synthesized rawMetadata carrying the
// entityID + SSO URL + cert — and returns the generated clientID/clientSecret.
func TestPolisCreateConnection_SAML(t *testing.T) {
	f := newFakePolis(t)
	p := newTestPolis(t, f)

	res, err := p.CreateConnection(context.Background(), ConnectionSpec{
		Alias:       "partner",
		DisplayName: "Partner SSO",
		Protocol:    "saml",
		Domain:      "Partner.Example.NET", // mixed case → must be lowercased into tenant
		Config: map[string]string{
			"entityId":               "https://idp.example.net/saml2?idpid=C01",
			"singleSignOnServiceUrl": "https://idp.example.net/saml2/sso?idpid=C01",
			"signingCertificate":     "-----BEGIN CERTIFICATE-----\nMIIDbody\n-----END CERTIFICATE-----",
		},
	})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}

	if f.gotAuth != "Api-Key test-key" {
		t.Errorf("auth header: got %q", f.gotAuth)
	}
	if !strings.HasPrefix(f.gotContentType, "application/x-www-form-urlencoded") {
		t.Errorf("content-type: got %q", f.gotContentType)
	}
	if f.gotForm["tenant"] != "partner.example.net" {
		t.Errorf("tenant: got %q want partner.example.net", f.gotForm["tenant"])
	}
	if f.gotForm["product"] != "steward" {
		t.Errorf("product: got %q want steward", f.gotForm["product"])
	}
	if f.gotForm["defaultRedirectUrl"] != "https://policies.example.org/auth/sso/callback" {
		t.Errorf("defaultRedirectUrl: got %q", f.gotForm["defaultRedirectUrl"])
	}
	var allow []string
	if err := json.Unmarshal([]byte(f.gotForm["redirectUrl"]), &allow); err != nil {
		t.Fatalf("redirectUrl not a JSON array: %v (%q)", err, f.gotForm["redirectUrl"])
	}
	if len(allow) != 1 || allow[0] != "https://policies.example.org/*" {
		t.Errorf("redirect allowlist: got %v", allow)
	}
	raw := f.gotForm["rawMetadata"]
	if !strings.Contains(raw, "entityID=\"https://idp.example.net/saml2?idpid=C01\"") {
		t.Errorf("rawMetadata missing entityID: %s", raw)
	}
	if !strings.Contains(raw, "MIIDbody") || strings.Contains(raw, "BEGIN CERTIFICATE") {
		t.Errorf("rawMetadata cert not normalized: %s", raw)
	}
	if !strings.Contains(raw, "Location=\"https://idp.example.net/saml2/sso?idpid=C01\"") {
		t.Errorf("rawMetadata missing SSO location: %s", raw)
	}

	if res.ClientID != "cid-123" || res.ClientSecret != "csec-456" {
		t.Errorf("result creds: got %+v", res)
	}
	if res.Tenant != "partner.example.net" || res.Product != "steward" {
		t.Errorf("result coords: got %+v", res)
	}
}

// TestPolisCreateConnection_RawMetadataVerbatim: a wizard-supplied rawMetadata
// is passed through unchanged rather than synthesized.
func TestPolisCreateConnection_RawMetadataVerbatim(t *testing.T) {
	f := newFakePolis(t)
	p := newTestPolis(t, f)

	const verbatim = `<EntityDescriptor entityID="verbatim-only"></EntityDescriptor>`
	_, err := p.CreateConnection(context.Background(), ConnectionSpec{
		Protocol: "saml",
		Domain:   "example.org",
		Config:   map[string]string{"rawMetadata": verbatim, "entityId": "ignored"},
	})
	if err != nil {
		t.Fatalf("CreateConnection: %v", err)
	}
	if f.gotForm["rawMetadata"] != verbatim {
		t.Errorf("expected verbatim rawMetadata, got %q", f.gotForm["rawMetadata"])
	}
}

// TestPolisCreateConnection_ErrorStatus surfaces a non-2xx Polis response as
// an error (so the caller runs its compensating DB delete).
func TestPolisCreateConnection_ErrorStatus(t *testing.T) {
	f := newFakePolis(t)
	f.createStatus = http.StatusBadRequest
	f.createBody = `{"error":{"message":"bad metadata"}}`
	p := newTestPolis(t, f)

	_, err := p.CreateConnection(context.Background(), ConnectionSpec{
		Protocol: "saml",
		Domain:   "example.org",
		Config: map[string]string{
			"entityId":               "https://idp",
			"singleSignOnServiceUrl": "https://idp/sso",
			"signingCertificate":     "AAAAbase64",
		},
	})
	if err == nil {
		t.Fatal("expected error on 400 from Polis")
	}
	if !strings.Contains(err.Error(), "bad metadata") {
		t.Errorf("error should carry Polis body: %v", err)
	}
}

// TestPolisDeleteConnection asserts the delete addresses the connection by
// clientID/clientSecret with the tenant/product coordinates.
func TestPolisDeleteConnection(t *testing.T) {
	f := newFakePolis(t)
	p := newTestPolis(t, f)

	if err := p.DeleteConnection(context.Background(), ConnectionRef{
		Tenant:       "example.org",
		Product:      "steward",
		ClientID:     "cid-123",
		ClientSecret: "csec-456",
	}); err != nil {
		t.Fatalf("DeleteConnection: %v", err)
	}
	if f.gotDeleteQuery["clientID"] != "cid-123" || f.gotDeleteQuery["clientSecret"] != "csec-456" {
		t.Errorf("delete query creds: got %+v", f.gotDeleteQuery)
	}
	if f.gotDeleteQuery["tenant"] != "example.org" || f.gotDeleteQuery["product"] != "steward" {
		t.Errorf("delete query coords: got %+v", f.gotDeleteQuery)
	}
	if f.gotAuth != "Api-Key test-key" {
		t.Errorf("delete auth header: got %q", f.gotAuth)
	}
}

func TestPolisCreateConnection_OIDCSendsTheClientSecret(t *testing.T) {
	f := newFakePolis(t)
	p := newTestPolis(t, f)
	_, err := p.CreateConnection(context.Background(), ConnectionSpec{
		Protocol:     "oidc",
		Domain:       "partner.example.net",
		ClientSecret: "resolved-secret",
		Config:       map[string]string{"issuer": "https://idp.example.net", "clientId": "steward"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if f.gotForm["oidcClientSecret"] != "resolved-secret" {
		t.Fatalf("oidcClientSecret: got %q", f.gotForm["oidcClientSecret"])
	}
}

func TestPolisUpdateOIDCSecret_PatchesTheConnection(t *testing.T) {
	f := newFakePolis(t)
	p := newTestPolis(t, f)
	err := p.UpdateOIDCSecret(context.Background(), ConnectionRef{
		Domain: "Partner.example.net", ClientID: "cid-123", ClientSecret: "csec-456",
	}, "new-oidc-secret")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	want := map[string]string{
		"clientID":         "cid-123",
		"clientSecret":     "csec-456",
		"tenant":           "partner.example.net",
		"product":          "steward",
		"oidcClientSecret": "new-oidc-secret",
	}
	for k, v := range want {
		if f.gotPatchForm[k] != v {
			t.Fatalf("%s: got %q want %q", k, f.gotPatchForm[k], v)
		}
	}
	if f.gotContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("content type: %q", f.gotContentType)
	}
	if f.gotAuth != "Api-Key test-key" {
		t.Fatalf("auth: %q", f.gotAuth)
	}
}

func TestPolisUpdateOIDCSecret_ErrorNeverCarriesTheSecret(t *testing.T) {
	f := newFakePolis(t)
	f.patchStatus = http.StatusBadRequest
	p := newTestPolis(t, f)
	err := p.UpdateOIDCSecret(context.Background(), ConnectionRef{
		Domain: "partner.example.net", ClientID: "cid-123", ClientSecret: "csec-456",
	}, "new-oidc-secret")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "new-oidc-secret") || strings.Contains(err.Error(), "csec-456") {
		t.Fatalf("error leaks a secret: %v", err)
	}
}

func TestPolisUpdateOIDCSecret_NeedsTheConnectionCoordinates(t *testing.T) {
	f := newFakePolis(t)
	p := newTestPolis(t, f)
	if err := p.UpdateOIDCSecret(context.Background(), ConnectionRef{Domain: "partner.example.net"}, "s"); err == nil {
		t.Fatal("want an error without the connection's client id and secret")
	}
	if f.gotPatchForm != nil {
		t.Fatal("nothing may be sent")
	}
}
