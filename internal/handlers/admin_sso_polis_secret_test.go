// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/sso/polis"
	"github.com/Steward-GRC/steward-identity/internal/sso/spkeys"
)

// fakeSecretStore is an in-memory spkeys.Store: the out-of-band secret store,
// standing in for the k8s Secret.
type fakeSecretStore struct {
	mu   sync.Mutex
	data map[string][]byte
	err  error
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{data: map[string][]byte{}}
}

func (f *fakeSecretStore) PutKey(_ context.Context, k string, v []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	f.data[k] = cp
	return nil
}

func (f *fakeSecretStore) GetKey(_ context.Context, k string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.data[k]
	if !ok {
		return nil, fmt.Errorf("no key %q: %w", k, spkeys.ErrKeyNotFound)
	}
	return v, nil
}

func (f *fakeSecretStore) DeleteKey(_ context.Context, k string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	delete(f.data, k)
	return nil
}

func (f *fakeSecretStore) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.data))
	for k := range f.data {
		out = append(out, k)
	}
	return out
}

// addPolisOrg onboards one SAML org through the Polis provisioner and returns
// the created connection's alias.
func addPolisOrg(t *testing.T, h *handlers.SSOAdminHandler, domain string) string {
	t.Helper()
	const cert = "-----BEGIN CERTIFICATE-----\nMIIDbodyABC\n-----END CERTIFICATE-----"
	resp, err := h.AddOrganization(adminCtx(uuid.NewString()), &identityv1.AddOrganizationRequest{
		OrgName:     "Partner Organisation",
		Domain:      domain,
		Protocol:    "saml",
		DisplayName: "Partner Organisation SSO",
		Config: map[string]string{
			"entityId":               "https://idp.example.net/o/saml2?idpid=C01",
			"singleSignOnServiceUrl": "https://idp.example.net/o/saml2/idp?idpid=C01",
			"signingCertificate":     cert,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetOrganization())
	return resp.GetOrganization().GetConnectionAlias()
}

// TestAddOrganization_PolisSecretNeverStoredInConfig is.
//
// The Polis client secret must not reach idp_connections.config, which is a
// plaintext JSONB column that lands in pg_dump output and in every WAL-G base
// backup and WAL segment. It must instead go to the out-of-band store, with
// only a non-secret reference persisted on config.
func TestAddOrganization_PolisSecretNeverStoredInConfig(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	secrets := newFakeSecretStore()
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).
		WithPolisSecrets(secrets)

	alias := addPolisOrg(t, h, "partner.example.net")

	conn, err := s.GetIdPConnectionByAlias(context.Background(), alias)
	require.NoError(t, err)

	// 1. The plaintext key is absent, and the secret VALUE appears under no key.
	_, present := conn.Config["polisClientSecret"]
	require.False(t, present, "config must not carry the plaintext polisClientSecret")
	for k, v := range conn.Config {
		require.NotEqual(t, "CSEC-xyz", v, "config key %q carries the plaintext client secret", k)
	}

	// 2. A non-secret reference IS persisted, and it addresses this connection.
	ref, _ := conn.Config[polis.ConfigKeyPolisClientSecretRef].(string)
	require.NotEmpty(t, ref, "config must carry a reference to the out-of-band secret")
	require.Equal(t, polis.PolisClientSecretRef(conn.ID.String()), ref)
	require.NotContains(t, ref, "CSEC-xyz", "the reference must not embed the secret")

	// 3. The secret really is in the out-of-band store under that reference.
	got, err := secrets.GetKey(context.Background(), ref)
	require.NoError(t, err, "secret must be retrievable from the out-of-band store")
	require.Equal(t, "CSEC-xyz", string(got))

	// 4. The non-secret teardown coordinates are still inline.
	require.Equal(t, "CID-abc", conn.Config[polis.ConfigKeyPolisClientID])
	require.Equal(t, "partner.example.net", conn.Config[polis.ConfigKeyPolisTenant])
	require.Equal(t, "steward", conn.Config[polis.ConfigKeyPolisProduct])
}

// TestDeleteOrganization_ResolvesPolisSecretAtUseTime proves the indirection is
// functional and not merely write-only: teardown must recover the secret from
// the out-of-band store and still address the Polis connection precisely.
func TestDeleteOrganization_ResolvesPolisSecretAtUseTime(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	secrets := newFakeSecretStore()
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).
		WithPolisSecrets(secrets)

	addPolisOrg(t, h, "partner.example.net")

	_, err := h.DeleteOrganization(adminCtx(uuid.NewString()),
		&identityv1.DeleteOrganizationRequest{Domain: "partner.example.net"})
	require.NoError(t, err)

	require.Equal(t, "CID-abc", f.deleteQuery["clientID"])
	require.Equal(t, "CSEC-xyz", f.deleteQuery["clientSecret"],
		"teardown must resolve the secret from the out-of-band store at use time")
	require.Equal(t, "partner.example.net", f.deleteQuery["tenant"])
	require.Equal(t, "steward", f.deleteQuery["product"])
}

// TestDeleteOrganization_NoSecretStore_FallsBackToTenantProduct is the
// migration-safety case, and the reason migration 0012 can simply CLEAR the
// compromised plaintext instead of moving it.
//
// A pre-#47 row whose plaintext was stripped — or any connection provisioned
// while the store was unwired — has no resolvable secret. Teardown must still
// work, addressing the connection by tenant/product, which Polis accepts and
// which is always populated.
func TestDeleteOrganization_NoSecretStore_FallsBackToTenantProduct(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	// No WithPolisSecrets: the indirection is unavailable, as in local dev.
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth())

	alias := addPolisOrg(t, h, "partner.example.net")

	// Nothing secret was persisted anywhere.
	conn, err := s.GetIdPConnectionByAlias(context.Background(), alias)
	require.NoError(t, err)
	_, present := conn.Config["polisClientSecret"]
	require.False(t, present, "no plaintext secret may be persisted even without a store")
	require.Empty(t, conn.Config[polis.ConfigKeyPolisClientSecretRef],
		"no reference may be recorded when the secret could not be stored")

	_, err = h.DeleteOrganization(adminCtx(uuid.NewString()),
		&identityv1.DeleteOrganizationRequest{Domain: "partner.example.net"})
	require.NoError(t, err, "teardown must succeed without the secret")

	// Addressed by tenant/product; no secret sent.
	require.Equal(t, "partner.example.net", f.deleteQuery["tenant"])
	require.Equal(t, "steward", f.deleteQuery["product"])
	require.Empty(t, f.deleteQuery["clientSecret"])
}
