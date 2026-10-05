// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package polis provisions organisations' SAML and OIDC connections in Ory
// Polis through its admin API. The onboarding registry, domain verification,
// connection tests and activation gates live in identity; Polis brokers the
// sign-in itself.
package polis

// ConnectionSpec is the input for one organisation's connection: the
// non-secret wizard settings plus the routing alias and the organisation's
// email domain, which Polis uses as the tenant.
type ConnectionSpec struct {
	// Alias is the connection's routing key. Polis uses it only as the
	// connection name when DisplayName is empty.
	Alias       string
	DisplayName string
	// Protocol is "oidc" or "saml".
	Protocol string
	// Domain is the organisation's email domain, lowercased.
	Domain string
	// SecretRef is the OIDC client-secret reference; SAML needs none.
	SecretRef string
	// Config is the wizard's settings. SAML: entityId, singleSignOnServiceUrl
	// and signingCertificate, or a verbatim rawMetadata or metadataUrl. OIDC:
	// issuer and clientId.
	Config map[string]string
}

// ConnectionResult is what Polis issued for a new connection, kept so the
// connection can be torn down later.
type ConnectionResult struct {
	ClientID     string
	ClientSecret string
	Tenant       string
	Product      string
}

// ConfigKeys returns the keys to store in the connection's config column so a
// later delete can address it. The column is plain JSONB, so the client
// secret is never one of them: it goes to the secret store, addressed by
// ConfigKeyPolisClientSecretRef.
func (r ConnectionResult) ConfigKeys() map[string]any {
	m := map[string]any{}
	if r.ClientID != "" {
		m[ConfigKeyPolisClientID] = r.ClientID
	}
	if r.Tenant != "" {
		m[ConfigKeyPolisTenant] = r.Tenant
	}
	if r.Product != "" {
		m[ConfigKeyPolisProduct] = r.Product
	}
	return m
}

// The config keys a Polis connection stores. All of them are non-secret.
const (
	ConfigKeyPolisClientID = "polisClientId"
	// ConfigKeyPolisClientSecretRef names the secret-store key the client
	// secret lives under; the reference itself holds no secret.
	ConfigKeyPolisClientSecretRef = "polisClientSecretRef" // #nosec G101 -- a config key name
	ConfigKeyPolisTenant          = "polisTenant"
	ConfigKeyPolisProduct         = "polisProduct"
)

// PolisClientSecretRef returns the secret-store key of a connection's client
// secret. It is derived from the connection id only, so a rotation overwrites
// the same slot.
func PolisClientSecretRef(connectionID string) string {
	return "polis-client-secret-" + connectionID
}

// ConnectionRef addresses a connection for teardown: by client id and secret,
// with tenant and product (or the domain) as its coordinates.
type ConnectionRef struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Tenant       string
	Product      string
}
