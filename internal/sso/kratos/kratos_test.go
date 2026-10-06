// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package kratos_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

// fakeKratos stands in for the Kratos admin API and records every call.
type fakeKratos struct {
	mu sync.Mutex

	knownEmail string
	identityID string

	lookupStatus   int
	patchStatus    int
	sessionsStatus int
	passwordStatus int

	lookupQuery  string
	patchBody    string
	patchPath    string
	sessionsPath string
	passwordPath string
	created      map[string]any
	updated      map[string]any
	disabled     string
	deleted      string
	activeQuery  string
	calls        []string
}

func (f *fakeKratos) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeKratos) sequence() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

const sessionsJSON = `[
 {"id":"5f0c1d2e-0000-4000-8000-000000000001","active":true,
  "issued_at":"2030-01-02T03:04:05Z","authenticated_at":"2030-01-02T03:04:05Z","expires_at":"2030-01-03T03:04:05Z",
  "devices":[{"id":"d1","ip_address":"192.0.2.10","user_agent":"Example Browser/1.0"}]},
 {"id":"5f0c1d2e-0000-4000-8000-000000000002","active":false,
  "issued_at":"2030-01-01T03:04:05Z","authenticated_at":"2030-01-01T03:04:05Z","expires_at":"2030-01-02T03:04:05Z"}
]`

const activeSessionsJSON = `[
 {"id":"5f0c1d2e-0000-4000-8000-000000000001","active":true,
  "issued_at":"2030-01-02T03:04:05Z","authenticated_at":"2030-01-02T03:04:05Z","expires_at":"2030-01-03T03:04:05Z"}
]`

func (f *fakeKratos) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/identities", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			f.record("create")
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			_ = json.Unmarshal(body, &f.created)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"` + f.identityID + `","schema_id":"default","schema_url":"http://kratos.example.org/schemas/default","state":"active","traits":{}}`))
			return
		}
		f.record("lookup")
		f.mu.Lock()
		f.lookupQuery = r.URL.Query().Get("credentials_identifier")
		f.mu.Unlock()
		if f.lookupStatus != 0 {
			w.WriteHeader(f.lookupStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("credentials_identifier") != f.knownEmail {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"` + f.identityID + `","schema_id":"default","schema_url":"http://kratos.example.org/schemas/default","state":"active","traits":{"email":"` + f.knownEmail + `"}}]`))
	})
	mux.HandleFunc("/admin/sessions/", func(w http.ResponseWriter, r *http.Request) {
		f.record("disable")
		f.mu.Lock()
		f.disabled = strings.TrimPrefix(r.URL.Path, "/admin/sessions/")
		f.mu.Unlock()
		if f.disabled == "unknown" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/admin/identities/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/sessions") && r.Method == http.MethodGet:
			f.record("list-sessions")
			f.mu.Lock()
			f.activeQuery = r.URL.Query().Get("active")
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if f.sessionsStatus != 0 {
				w.WriteHeader(f.sessionsStatus)
				return
			}
			if r.URL.Query().Get("active") == "true" {
				_, _ = w.Write([]byte(activeSessionsJSON))
				return
			}
			_, _ = w.Write([]byte(sessionsJSON))
		case strings.HasSuffix(path, "/sessions") && r.Method == http.MethodDelete:
			f.record("sessions")
			f.mu.Lock()
			f.sessionsPath = path
			f.mu.Unlock()
			if f.sessionsStatus != 0 {
				w.WriteHeader(f.sessionsStatus)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/credentials/password") && r.Method == http.MethodDelete:
			f.record("password")
			f.mu.Lock()
			f.passwordPath = path
			f.mu.Unlock()
			if f.passwordStatus != 0 {
				w.WriteHeader(f.passwordStatus)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch:
			f.record("patch")
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.patchBody = string(body)
			f.patchPath = path
			f.mu.Unlock()
			if f.patchStatus != 0 {
				w.WriteHeader(f.patchStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"` + f.identityID + `","schema_id":"default","schema_url":"http://kratos.example.org/schemas/default","state":"inactive","traits":{}}`))
		case r.Method == http.MethodDelete:
			f.record("delete")
			f.mu.Lock()
			f.deleted = strings.TrimPrefix(path, "/admin/identities/")
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet:
			f.record("get")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"` + f.identityID + `","schema_id":"default","schema_url":"http://kratos.example.org/schemas/default","state":"active","traits":{"email":"` + f.knownEmail + `","username":"bob","name":"Bob"}}`))
		case r.Method == http.MethodPut:
			f.record("update")
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			_ = json.Unmarshal(body, &f.updated)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"` + f.identityID + `","schema_id":"default","schema_url":"http://kratos.example.org/schemas/default","state":"active","traits":{}}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

const (
	bobEmail = "bob@example.org"
	bobID    = "47feeda5-40bc-47a2-acc9-8a063eebed18"
)

// Deactivate first: if a later step fails, Kratos already refuses the account.
func TestRevokeIdentityDeactivatesRevokesSessionsAndDropsPassword(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: bobID}
	srv := f.server(t)

	res, err := kratos.New(srv.URL, 5*time.Second).RevokeIdentity(context.Background(), f.knownEmail)
	require.NoError(t, err)
	require.True(t, res.Found)
	require.Equal(t, f.identityID, res.IdentityID)
	require.True(t, res.Deactivated)
	require.True(t, res.SessionsRevoked)
	require.True(t, res.PasswordRemoved)

	require.Equal(t, f.knownEmail, f.lookupQuery)
	require.Equal(t, "/admin/identities/"+f.identityID, f.patchPath)
	require.Contains(t, f.patchBody, `"/state"`)
	require.Contains(t, f.patchBody, `"inactive"`)
	require.Equal(t, "/admin/identities/"+f.identityID+"/sessions", f.sessionsPath)
	require.Equal(t, "/admin/identities/"+f.identityID+"/credentials/password", f.passwordPath)
	require.Equal(t, []string{"lookup", "patch", "sessions", "password"}, f.sequence())
}

// An SSO-only account has no Kratos identity; deleting it must not fail.
func TestRevokeIdentityNoKratosIdentityIsNotAnError(t *testing.T) {
	f := &fakeKratos{knownEmail: "erin@example.org", identityID: "kratos-1"}
	srv := f.server(t)

	res, err := kratos.New(srv.URL, 5*time.Second).RevokeIdentity(context.Background(), "ivan@partner.example.net")
	require.NoError(t, err)
	require.False(t, res.Found)
	require.Equal(t, []string{"lookup"}, f.sequence())
}

func TestRevokeIdentityDeactivateFailureIsAnError(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: "kratos-1", patchStatus: http.StatusInternalServerError}
	srv := f.server(t)

	_, err := kratos.New(srv.URL, 5*time.Second).RevokeIdentity(context.Background(), bobEmail)
	require.Error(t, err)
}

func TestRevokeIdentityTolerates404OnPasswordCredential(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: "kratos-1", passwordStatus: http.StatusNotFound}
	srv := f.server(t)

	res, err := kratos.New(srv.URL, 5*time.Second).RevokeIdentity(context.Background(), bobEmail)
	require.NoError(t, err)
	require.True(t, res.Deactivated)
	require.False(t, res.PasswordRemoved)
}

func TestRevokeIdentityLookupFailureIsAnError(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: "kratos-1", lookupStatus: http.StatusBadGateway}
	srv := f.server(t)

	_, err := kratos.New(srv.URL, 5*time.Second).RevokeIdentity(context.Background(), bobEmail)
	require.Error(t, err)
}

func TestRevokeIdentityTransportFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := kratos.New(url, 500*time.Millisecond).RevokeIdentity(context.Background(), bobEmail)
	require.Error(t, err)
}

func TestRevokeIdentityEmptyEmailIsAnError(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: "kratos-1"}
	srv := f.server(t)

	_, err := kratos.New(srv.URL, 5*time.Second).RevokeIdentity(context.Background(), "")
	require.ErrorIs(t, err, kratos.ErrNoEmail)
	require.Empty(t, f.sequence())
}

func TestFindIdentityIsReadOnly(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: bobID}
	srv := f.server(t)

	ref, err := kratos.New(srv.URL, 5*time.Second).FindIdentity(context.Background(), bobEmail)
	require.NoError(t, err)
	require.Equal(t, kratos.IdentityRef{ID: bobID, Found: true, State: "active"}, ref)
	require.Equal(t, []string{"lookup"}, f.sequence())
}

func TestCreateIdentitySendsTraitsAndPassword(t *testing.T) {
	f := &fakeKratos{identityID: bobID}
	srv := f.server(t)

	id, err := kratos.New(srv.URL, 5*time.Second, kratos.WithSchemaID("staff")).CreateIdentity(context.Background(),
		kratos.Account{Username: "bob", Email: bobEmail, Name: "Bob"}, "correct horse battery staple")
	require.NoError(t, err)
	require.Equal(t, bobID, id)
	require.Equal(t, "staff", f.created["schema_id"])
	require.Equal(t, map[string]any{"email": bobEmail, "username": "bob", "name": "Bob"}, f.created["traits"])
	cred := f.created["credentials"].(map[string]any)["password"].(map[string]any)["config"].(map[string]any)
	require.Equal(t, "correct horse battery staple", cred["password"])
}

func TestSetPasswordKeepsTraitsAndState(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: bobID}
	srv := f.server(t)

	require.NoError(t, kratos.New(srv.URL, 5*time.Second).SetPassword(context.Background(), bobID, "a new passphrase"))
	require.Equal(t, []string{"get", "update"}, f.sequence())
	require.Equal(t, "active", f.updated["state"])
	require.Equal(t, "default", f.updated["schema_id"])
	require.Equal(t, bobEmail, f.updated["traits"].(map[string]any)["email"])
	cred := f.updated["credentials"].(map[string]any)["password"].(map[string]any)["config"].(map[string]any)
	require.Equal(t, "a new passphrase", cred["password"])
}

func TestUpdateProfileReplacesEmailAndName(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: bobID}
	srv := f.server(t)

	require.NoError(t, kratos.New(srv.URL, 5*time.Second).UpdateProfile(context.Background(), bobID, "bob.b@example.org", "Bob B"))
	traits := f.updated["traits"].(map[string]any)
	require.Equal(t, "bob.b@example.org", traits["email"])
	require.Equal(t, "Bob B", traits["name"])
	require.Equal(t, "bob", traits["username"], "other traits are kept")
	require.Nil(t, f.updated["credentials"], "a profile update never touches the password")
}

// The session surface used to drop the device IP Kratos records; it now
// reads it the same way it already read the user agent (steward-web#27).
func TestListSessionsMapsTheSessionsAndTheirIP(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: bobID}
	srv := f.server(t)

	ss, err := kratos.New(srv.URL, 5*time.Second).ListSessions(context.Background(), bobID)
	require.NoError(t, err)
	require.Len(t, ss, 2)
	require.Equal(t, "5f0c1d2e-0000-4000-8000-000000000001", ss[0].ID)
	require.True(t, ss[0].Active)
	require.Equal(t, "Example Browser/1.0", ss[0].UserAgent)
	require.Equal(t, "192.0.2.10", ss[0].ClientIP)
	require.Equal(t, time.Date(2030, 1, 3, 3, 4, 5, 0, time.UTC), ss[0].ExpiresAt.UTC())
	require.False(t, ss[1].Active)
	require.Empty(t, ss[1].UserAgent)
	require.Empty(t, ss[1].ClientIP)
}

func TestListSessionsFailureIsAnError(t *testing.T) {
	f := &fakeKratos{identityID: bobID, sessionsStatus: http.StatusBadGateway}
	srv := f.server(t)

	_, err := kratos.New(srv.URL, 5*time.Second).ListSessions(context.Background(), bobID)
	require.Error(t, err)
}

func TestRevokeIdentitySessionsCountsTheActiveOnes(t *testing.T) {
	f := &fakeKratos{knownEmail: bobEmail, identityID: bobID}
	srv := f.server(t)

	n, err := kratos.New(srv.URL, 5*time.Second).RevokeIdentitySessions(context.Background(), bobID)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, "true", f.activeQuery)
	require.Equal(t, []string{"list-sessions", "sessions"}, f.sequence())
}

func TestRevokeSessionDisablesOneSession(t *testing.T) {
	f := &fakeKratos{identityID: bobID}
	srv := f.server(t)
	c := kratos.New(srv.URL, 5*time.Second)

	revoked, err := c.RevokeSession(context.Background(), "5f0c1d2e-0000-4000-8000-000000000001")
	require.NoError(t, err)
	require.True(t, revoked)
	require.Equal(t, "5f0c1d2e-0000-4000-8000-000000000001", f.disabled)

	revoked, err = c.RevokeSession(context.Background(), "unknown")
	require.NoError(t, err, "an unknown session is not an error")
	require.False(t, revoked)
}

func TestDeleteIdentityRemovesIt(t *testing.T) {
	f := &fakeKratos{identityID: bobID}
	srv := f.server(t)

	require.NoError(t, kratos.New(srv.URL, 5*time.Second).DeleteIdentity(context.Background(), bobID))
	require.Equal(t, bobID, f.deleted)
}
