// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package polis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultProduct is the Polis product every Steward connection lives under.
const DefaultProduct = "steward"

const ssoPath = "/api/v1/sso"

// Config configures the Polis admin client.
type Config struct {
	// BaseURL is the Polis admin base URL.
	BaseURL string
	// APIKey authenticates admin calls, sent as "Authorization: Api-Key <key>".
	APIKey string
	// Product is the Polis product connections live under; DefaultProduct
	// when empty.
	Product string
	// GatewayBaseURL is the gateway's external base URL: the default redirect
	// is <base>/auth/sso/callback and the redirect allowlist is <base>/*.
	GatewayBaseURL string
	// HTTPClient is the transport; nil gets a 15-second timeout.
	HTTPClient *http.Client
}

// Client provisions Polis connections keyed by tenant (the organisation's
// email domain) and product. For SAML it builds the IdP metadata from the
// wizard's three fields when no metadata document or URL was given.
type Client struct {
	baseURL    string
	apiKey     string
	product    string
	gatewayURL string
	http       *http.Client
}

// New builds a Client.
func New(cfg Config) *Client {
	product := cfg.Product
	if product == "" {
		product = DefaultProduct
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:     cfg.APIKey,
		product:    product,
		gatewayURL: strings.TrimRight(cfg.GatewayBaseURL, "/"),
		http:       httpClient,
	}
}

// createResponse is the part of the create answer kept: the client id and
// secret that address the connection on delete.
type createResponse struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
}

// CreateConnection creates the connection in Polis and returns what a later
// delete needs. On an error nothing was created.
func (p *Client) CreateConnection(ctx context.Context, spec ConnectionSpec) (ConnectionResult, error) {
	tenant := strings.ToLower(strings.TrimSpace(spec.Domain))
	if tenant == "" {
		return ConnectionResult{}, fmt.Errorf("polis: domain (tenant) is required")
	}
	if p.gatewayURL == "" {
		return ConnectionResult{}, fmt.Errorf("polis: gateway base URL is required for redirect allowlist")
	}

	form, err := p.buildCreateForm(tenant, spec)
	if err != nil {
		return ConnectionResult{}, err
	}

	body, err := p.do(ctx, http.MethodPost, nil, strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded")
	if err != nil {
		return ConnectionResult{}, err
	}

	var out createResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return ConnectionResult{}, fmt.Errorf("polis: decode create response: %w", err)
	}
	if out.ClientID == "" || out.ClientSecret == "" {
		return ConnectionResult{}, fmt.Errorf("polis: create response missing clientID/clientSecret")
	}
	return ConnectionResult{
		ClientID:     out.ClientID,
		ClientSecret: out.ClientSecret,
		Tenant:       tenant,
		Product:      p.product,
	}, nil
}

// buildCreateForm prefers a metadata document or URL the wizard supplied and
// builds one from the SAML fields otherwise.
func (p *Client) buildCreateForm(tenant string, spec ConnectionSpec) (url.Values, error) {
	name := spec.DisplayName
	if name == "" {
		name = spec.Alias
	}
	if name == "" {
		name = tenant
	}

	redirectAllowlist, err := json.Marshal([]string{p.gatewayURL + "/*"})
	if err != nil {
		return nil, fmt.Errorf("polis: marshal redirect allowlist: %w", err)
	}

	form := url.Values{}
	form.Set("tenant", tenant)
	form.Set("product", p.product)
	form.Set("name", name)
	form.Set("description", "Steward SSO connection for "+tenant)
	form.Set("defaultRedirectUrl", p.gatewayURL+"/auth/sso/callback")
	form.Set("redirectUrl", string(redirectAllowlist))

	switch spec.Protocol {
	case "oidc":
		if issuer := spec.Config["issuer"]; issuer != "" {
			form.Set("oidcDiscoveryUrl", issuer)
		}
		if clientID := spec.Config["clientId"]; clientID != "" {
			form.Set("oidcClientId", clientID)
		}
		if spec.SecretRef != "" {
			form.Set("oidcClientSecret", spec.SecretRef)
		}
	default: // saml
		if raw := spec.Config["rawMetadata"]; strings.TrimSpace(raw) != "" {
			form.Set("rawMetadata", raw)
		} else if mdURL := spec.Config["metadataUrl"]; strings.TrimSpace(mdURL) != "" {
			form.Set("metadataUrl", mdURL)
		} else {
			md, err := SynthesizeSAMLIdPMetadata(
				spec.Config["entityId"],
				spec.Config["singleSignOnServiceUrl"],
				spec.Config["signingCertificate"],
			)
			if err != nil {
				return nil, err
			}
			form.Set("rawMetadata", md)
		}
	}
	return form, nil
}

// DeleteConnection removes a connection by its client id and secret, or by
// tenant and product when those are missing.
func (p *Client) DeleteConnection(ctx context.Context, ref ConnectionRef) error {
	q := url.Values{}
	tenant := ref.Tenant
	if tenant == "" {
		tenant = strings.ToLower(strings.TrimSpace(ref.Domain))
	}
	product := ref.Product
	if product == "" {
		product = p.product
	}
	q.Set("tenant", tenant)
	q.Set("product", product)
	if ref.ClientID != "" {
		q.Set("clientID", ref.ClientID)
	}
	if ref.ClientSecret != "" {
		q.Set("clientSecret", ref.ClientSecret)
	}
	_, err := p.do(ctx, http.MethodDelete, q, nil, "")
	return err
}

// do sends an authenticated request to the SSO endpoint. A non-2xx status is
// an error carrying Polis's answer.
func (p *Client) do(ctx context.Context, method string, query url.Values, body io.Reader, contentType string) ([]byte, error) {
	u := p.baseURL + ssoPath
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("polis: build request: %w", err)
	}
	req.Header.Set("Authorization", "Api-Key "+p.apiKey)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("polis: %s %s: %w", method, ssoPath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("polis: %s %s: status %d: %s", method, ssoPath, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}
