// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Bugs5382/go-log"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

const plainClientSecret = "aaaa-bbbb-test-only" // #nosec G101 -- test value

// dumpDatabase returns every row of every table in the test database as JSON
// text, so a test can prove a value was never written anywhere.
func dumpDatabase(t *testing.T, s *store.Store) string {
	t.Helper()
	v, ok := testDSNs.Load(s)
	require.True(t, ok, "store did not come from newTestStore")
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, v.(string))
	require.NoError(t, err)
	defer pool.Close()
	rows, err := pool.Query(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	require.NoError(t, err)
	var tables []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		tables = append(tables, n)
	}
	rows.Close()
	require.NotEmpty(t, tables)
	var b strings.Builder
	for _, tbl := range tables {
		r, err := pool.Query(ctx, fmt.Sprintf(`SELECT row_to_json(t)::text FROM %q t`, tbl))
		require.NoError(t, err)
		for r.Next() {
			var line string
			require.NoError(t, r.Scan(&line))
			b.WriteString(line)
			b.WriteByte('\n')
		}
		r.Close()
	}
	return b.String()
}

// captureLogs routes the handlers' logger into a buffer at trace level.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	t.Setenv("LOG_LEVEL", "trace")
	var buf bytes.Buffer
	restore := handlers.SetLoggerForTest(log.NewLoggerWithOptions("identity",
		log.WithOutput(&buf), log.WithDefaultLevel(log.LevelTrace)))
	t.Cleanup(restore)
	return &buf
}

func requireNoSecret(t *testing.T, where, text string) {
	t.Helper()
	require.NotContains(t, text, plainClientSecret, "the client secret leaked into %s", where)
}

func requireNoSecretInMessage(t *testing.T, m proto.Message) {
	t.Helper()
	b, err := protojson.Marshal(m)
	require.NoError(t, err)
	requireNoSecret(t, "the response", string(b))
}

func oidcAddRequest(domain string) *identityv1.AddOrganizationRequest {
	return &identityv1.AddOrganizationRequest{
		OrgName:     "Partner Organisation",
		Domain:      domain,
		Protocol:    "oidc",
		DisplayName: "Partner Organisation SSO",
		Config:      map[string]string{"issuer": "https://idp.partner.example.net", "clientId": "steward"},
	}
}

func TestAddOrganization_ClientSecret_GoesToSecretStoreNeverDBResponseOrLog(t *testing.T) {
	logs := captureLogs(t)
	s := newTestStore(t)
	f := newPolisFake(t)
	secrets := newFakeSecretStore()
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).WithPolisSecrets(secrets)

	req := oidcAddRequest("partner.example.net")
	req.ClientSecret = plainClientSecret
	resp, err := h.AddOrganization(adminCtx(uuid.NewString()), req)
	require.NoError(t, err)

	require.Equal(t, plainClientSecret, f.createForm["oidcClientSecret"], "Polis must get the secret itself")

	conn, err := s.GetIdPConnectionByAlias(context.Background(), resp.GetOrganization().GetConnectionAlias())
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(conn.SecretRef, "oidc-client-secret-"), "secret_ref names the stored key, got a value of length %d", len(conn.SecretRef))
	stored, err := secrets.GetKey(context.Background(), conn.SecretRef)
	require.NoError(t, err)
	require.Equal(t, plainClientSecret, string(stored))

	requireNoSecret(t, "the database", dumpDatabase(t, s))
	requireNoSecretInMessage(t, resp)
	requireNoSecret(t, "the logs", logs.String())
	require.False(t, resp.GetOrganization().GetSecretReentryRequired())
}

func TestAddOrganization_SecretRef_ResolvesPreCreatedKey(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	secrets := newFakeSecretStore()
	require.NoError(t, secrets.PutKey(context.Background(), "partner-oidc", []byte(plainClientSecret)))
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).WithPolisSecrets(secrets)

	req := oidcAddRequest("partner.example.net")
	req.SecretRef = "partner-oidc"
	resp, err := h.AddOrganization(adminCtx(uuid.NewString()), req)
	require.NoError(t, err)

	require.Equal(t, plainClientSecret, f.createForm["oidcClientSecret"], "Polis must get the resolved secret, not the reference")
	conn, err := s.GetIdPConnectionByAlias(context.Background(), resp.GetOrganization().GetConnectionAlias())
	require.NoError(t, err)
	require.Equal(t, "partner-oidc", conn.SecretRef)
	requireNoSecret(t, "the database", dumpDatabase(t, s))
	requireNoSecretInMessage(t, resp)
}

func TestAddOrganization_SecretInputsRefusedBeforePolis(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*identityv1.AddOrganizationRequest)
		noStore  bool
		wantCode codes.Code
	}{
		{"unknown reference", func(r *identityv1.AddOrganizationRequest) { r.SecretRef = "not-created" }, false, codes.InvalidArgument},
		{"malformed reference", func(r *identityv1.AddOrganizationRequest) { r.SecretRef = plainClientSecret + " with spaces/slashes" }, false, codes.InvalidArgument},
		{"reserved reference", func(r *identityv1.AddOrganizationRequest) { r.SecretRef = "polis-client-secret-" + uuid.NewString() }, false, codes.InvalidArgument},
		{"both reference and secret", func(r *identityv1.AddOrganizationRequest) {
			r.SecretRef = "partner-oidc"
			r.ClientSecret = plainClientSecret
		}, false, codes.InvalidArgument},
		{"secret in config", func(r *identityv1.AddOrganizationRequest) {
			r.ClientSecret = plainClientSecret
			r.Config["clientSecret"] = plainClientSecret
		}, false, codes.InvalidArgument},
		{"saml with a secret", func(r *identityv1.AddOrganizationRequest) {
			r.Protocol = "saml"
			r.ClientSecret = plainClientSecret
		}, false, codes.InvalidArgument},
		{"no secret store", func(r *identityv1.AddOrganizationRequest) { r.ClientSecret = plainClientSecret }, true, codes.FailedPrecondition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			s := newTestStore(t)
			f := newPolisFake(t)
			secrets := newFakeSecretStore()
			require.NoError(t, secrets.PutKey(context.Background(), "partner-oidc", []byte("other")))
			h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth())
			if !tc.noStore {
				h = h.WithPolisSecrets(secrets)
			}
			req := oidcAddRequest("partner.example.net")
			tc.mutate(req)

			_, err := h.AddOrganization(adminCtx(uuid.NewString()), req)
			require.Error(t, err)
			require.Equal(t, tc.wantCode, status.Code(err), err.Error())
			requireNoSecret(t, "the error", err.Error())
			require.Nil(t, f.createForm, "nothing may reach Polis")
			domains, lerr := s.ListSSODomains(context.Background())
			require.NoError(t, lerr)
			require.Empty(t, domains)
			requireNoSecret(t, "the database", dumpDatabase(t, s))
			requireNoSecret(t, "the logs", logs.String())
			require.ElementsMatch(t, []string{"partner-oidc"}, secrets.keys(), "nothing is written to the secret store")
		})
	}
}

func TestUpdateIdPConnection_ClientSecret_RotatesInPolisAndStore(t *testing.T) {
	logs := captureLogs(t)
	s := newTestStore(t)
	f := newPolisFake(t)
	secrets := newFakeSecretStore()
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).WithPolisSecrets(secrets)

	req := oidcAddRequest("partner.example.net")
	req.ClientSecret = "first-secret-value"
	added, err := h.AddOrganization(adminCtx(uuid.NewString()), req)
	require.NoError(t, err)
	before, err := s.GetIdPConnectionByAlias(context.Background(), added.GetOrganization().GetConnectionAlias())
	require.NoError(t, err)

	resp, err := h.UpdateIdPConnection(adminCtx(uuid.NewString()), &identityv1.UpdateIdPConnectionRequest{
		Domain:       "partner.example.net",
		ClientSecret: plainClientSecret,
	})
	require.NoError(t, err)

	require.Equal(t, plainClientSecret, f.patchForm["oidcClientSecret"])
	require.Equal(t, "CID-abc", f.patchForm["clientID"])
	require.Equal(t, "CSEC-xyz", f.patchForm["clientSecret"], "Polis addresses the connection by its own issued secret")
	require.Equal(t, "partner.example.net", f.patchForm["tenant"])
	require.Equal(t, "steward", f.patchForm["product"])

	after, err := s.GetIdPConnection(context.Background(), before.ID)
	require.NoError(t, err)
	got, err := secrets.GetKey(context.Background(), after.SecretRef)
	require.NoError(t, err)
	require.Equal(t, plainClientSecret, string(got))
	if after.SecretRef != before.SecretRef {
		_, err = secrets.GetKey(context.Background(), before.SecretRef)
		require.Error(t, err, "the replaced key identity owned is removed")
	}

	requireNoSecret(t, "the database", dumpDatabase(t, s))
	requireNoSecretInMessage(t, resp)
	requireNoSecret(t, "the logs", logs.String())
}

func TestUpdateIdPConnection_SecretOnSAMLRefused(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).WithPolisSecrets(newFakeSecretStore())
	addPolisOrg(t, h, "partner.example.net")

	_, err := h.UpdateIdPConnection(adminCtx(uuid.NewString()), &identityv1.UpdateIdPConnectionRequest{
		Domain:       "partner.example.net",
		ClientSecret: plainClientSecret,
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Nil(t, f.patchForm)
}

func TestChangeOrgProtocol_ToOIDC_ClientSecretNeverDBResponseOrLog(t *testing.T) {
	logs := captureLogs(t)
	s := newTestStore(t)
	f := newPolisFake(t)
	secrets := newFakeSecretStore()
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).WithPolisSecrets(secrets)
	addPolisOrg(t, h, "partner.example.net")

	resp, err := h.ChangeOrgProtocol(adminCtx(uuid.NewString()), &identityv1.ChangeOrgProtocolRequest{
		Domain:       "partner.example.net",
		Protocol:     "oidc",
		Config:       map[string]string{"issuer": "https://idp.partner.example.net", "clientId": "steward"},
		ClientSecret: plainClientSecret,
	})
	require.NoError(t, err)
	require.Equal(t, plainClientSecret, f.createForm["oidcClientSecret"])

	requireNoSecret(t, "the database", dumpDatabase(t, s))
	requireNoSecretInMessage(t, resp)
	requireNoSecret(t, "the logs", logs.String())
}

func TestChangeOrgProtocol_UnknownSecretRefRefusedBeforePolis(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).WithPolisSecrets(newFakeSecretStore())
	addPolisOrg(t, h, "partner.example.net")
	f.createForm = nil

	_, err := h.ChangeOrgProtocol(adminCtx(uuid.NewString()), &identityv1.ChangeOrgProtocolRequest{
		Domain:    "partner.example.net",
		Protocol:  "oidc",
		Config:    map[string]string{"issuer": "https://idp.partner.example.net", "clientId": "steward"},
		SecretRef: "not-created",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Nil(t, f.createForm, "nothing may reach Polis")
	require.Nil(t, f.deleteQuery, "the old connection stays in place")
}

func TestDeleteOrganization_RemovesTheClientSecretIdentityStored(t *testing.T) {
	s := newTestStore(t)
	f := newPolisFake(t)
	secrets := newFakeSecretStore()
	require.NoError(t, secrets.PutKey(context.Background(), "operator-key", []byte("kept")))
	h := handlers.NewSSOAdminHandler(s, f.provisioner(), ssoAdminAuth()).WithPolisSecrets(secrets)
	req := oidcAddRequest("partner.example.net")
	req.ClientSecret = plainClientSecret
	_, err := h.AddOrganization(adminCtx(uuid.NewString()), req)
	require.NoError(t, err)

	_, err = h.DeleteOrganization(adminCtx(uuid.NewString()), &identityv1.DeleteOrganizationRequest{Domain: "partner.example.net"})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"operator-key"}, secrets.keys(), "an operator's pre-created key is never removed")
}

func TestClearUnresolvableSecretRefs_WipesPlaintextAndFlagsReentry(t *testing.T) {
	logs := captureLogs(t)
	ctx := context.Background()
	s := newTestStore(t)
	secrets := newFakeSecretStore()
	require.NoError(t, secrets.PutKey(ctx, "kept-key", []byte("v")))
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).WithPolisSecrets(secrets)

	seed := func(alias, ref string) uuid.UUID {
		c, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: alias, Protocol: "oidc", ConnectionAlias: alias, SecretRef: ref})
		require.NoError(t, err)
		return c.ID
	}
	plain := seed("plain", plainClientSecret+" !")
	missing := seed("missing", "wellformedbutabsent")
	kept := seed("kept", "kept-key")
	empty := seed("empty", "")

	cleared, err := h.ClearUnresolvableSecretRefs(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, cleared)

	for _, id := range []uuid.UUID{plain, missing} {
		c, err := s.GetIdPConnection(ctx, id)
		require.NoError(t, err)
		require.Empty(t, c.SecretRef)
		require.True(t, c.SecretReentryRequired)
	}
	c, err := s.GetIdPConnection(ctx, kept)
	require.NoError(t, err)
	require.Equal(t, "kept-key", c.SecretRef)
	require.False(t, c.SecretReentryRequired)
	c, err = s.GetIdPConnection(ctx, empty)
	require.NoError(t, err)
	require.False(t, c.SecretReentryRequired)

	requireNoSecret(t, "the database", dumpDatabase(t, s))
	requireNoSecret(t, "the logs", logs.String())
	require.NotContains(t, logs.String(), "wellformedbutabsent", "only a count is logged")
}

func TestClearUnresolvableSecretRefs_StoreErrorClearsNothing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	secrets := newFakeSecretStore()
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).WithPolisSecrets(secrets)
	c, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "o", Protocol: "oidc", ConnectionAlias: "o", SecretRef: "maybe-there"})
	require.NoError(t, err)
	secrets.err = fmt.Errorf("apiserver unavailable")

	cleared, err := h.ClearUnresolvableSecretRefs(ctx)
	require.Error(t, err)
	require.Zero(t, cleared)
	got, gerr := s.GetIdPConnection(ctx, c.ID)
	require.NoError(t, gerr)
	require.Equal(t, "maybe-there", got.SecretRef, "an unreachable store must not wipe a reference that may be valid")
}

func TestListOrganizations_ShowsSecretReentryRequired(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	h := handlers.NewSSOAdminHandler(s, newPolisFake(t).provisioner(), ssoAdminAuth()).WithPolisSecrets(newFakeSecretStore())
	c, err := s.CreateIdPConnection(ctx, store.IdPConnection{OrgName: "o", Protocol: "oidc", ConnectionAlias: "o", SecretRef: plainClientSecret})
	require.NoError(t, err)
	id := c.ID
	_, err = s.UpsertSSODomain(ctx, store.SSODomain{Domain: "o.example.net", Method: "sso", ConnectionID: &id})
	require.NoError(t, err)
	_, err = h.ClearUnresolvableSecretRefs(ctx)
	require.NoError(t, err)

	resp, err := h.ListOrganizations(adminCtx(uuid.NewString()), &identityv1.ListOrganizationsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetOrganizations(), 1)
	require.True(t, resp.GetOrganizations()[0].GetSecretReentryRequired())
	requireNoSecretInMessage(t, resp)
}
