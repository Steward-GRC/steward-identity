// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package kratos_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

const (
	fakeToken   = "tok-secret-value"
	fakeCurrent = "the-current-pw"
)

// fakePublic stands in for the Kratos public API: the native login flow, the
// native settings flow and the native logout. It records every call.
type fakePublic struct {
	mu sync.Mutex

	identifier string
	// loginStatus, when set, answers every login post with it.
	loginStatus int
	// settingsMessage is the message id the settings post answers with a 400.
	settingsMessage int
	settingsStatus  int
	flowStatus      int

	calls       []string
	loginBody   map[string]string
	settingBody map[string]string
	settingAuth string
	logoutBody  map[string]string
}

func (f *fakePublic) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/self-service/login/api", func(w http.ResponseWriter, _ *http.Request) {
		f.record("login-flow")
		if f.flowStatus != 0 {
			w.WriteHeader(f.flowStatus)
			return
		}
		writeJSON(w, 200, map[string]any{"id": "login-flow-1"})
	})
	mux.HandleFunc("/self-service/login", func(w http.ResponseWriter, r *http.Request) {
		f.record("login")
		body := readBody(r)
		f.mu.Lock()
		f.loginBody = body
		f.mu.Unlock()
		if f.loginStatus != 0 {
			w.WriteHeader(f.loginStatus)
			return
		}
		if body["identifier"] != f.identifier || body["password"] != fakeCurrent || body["method"] != "password" ||
			r.URL.Query().Get("flow") != "login-flow-1" {
			writeJSON(w, 400, map[string]any{"ui": map[string]any{"messages": []map[string]any{
				{"id": 4000006, "text": "The provided credentials are invalid.", "type": "error"}}}})
			return
		}
		writeJSON(w, 200, map[string]any{"session_token": fakeToken, "session": map[string]any{"id": "sess-1"}})
	})
	mux.HandleFunc("/self-service/settings/api", func(w http.ResponseWriter, r *http.Request) {
		f.record("settings-flow")
		f.mu.Lock()
		f.settingAuth = r.Header.Get("X-Session-Token")
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"id": "settings-flow-1"})
	})
	mux.HandleFunc("/self-service/settings", func(w http.ResponseWriter, r *http.Request) {
		f.record("settings")
		body := readBody(r)
		f.mu.Lock()
		f.settingBody = body
		f.settingAuth = r.Header.Get("X-Session-Token")
		f.mu.Unlock()
		if f.settingsStatus != 0 {
			w.WriteHeader(f.settingsStatus)
			return
		}
		if f.settingsMessage != 0 {
			writeJSON(w, 400, map[string]any{"ui": map[string]any{"nodes": []map[string]any{
				{"messages": []map[string]any{{"id": f.settingsMessage, "text": "policy", "type": "error"}}}}}})
			return
		}
		writeJSON(w, 200, map[string]any{"state": "success"})
	})
	mux.HandleFunc("/self-service/logout/api", func(w http.ResponseWriter, r *http.Request) {
		f.record("logout")
		f.mu.Lock()
		f.logoutBody = readBody(r)
		f.mu.Unlock()
		w.WriteHeader(204)
	})
	return mux
}

func (f *fakePublic) record(c string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
}

func readBody(r *http.Request) map[string]string {
	b, _ := io.ReadAll(r.Body)
	out := map[string]string{}
	_ = json.Unmarshal(b, &out)
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newPublic(t *testing.T, f *fakePublic) *kratos.Public {
	t.Helper()
	f.identifier = "ada@example.org"
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return kratos.NewPublic(srv.URL+"/", time.Second)
}

func TestChangePassword_ChecksTheCurrentOneThenAppliesTheNewOneAndSignsTheCheckOut(t *testing.T) {
	f := &fakePublic{}
	p := newPublic(t, f)

	require.NoError(t, p.ChangePassword(t.Context(), "ada@example.org", fakeCurrent, "a-brand-new-long-pw"))

	require.Equal(t, []string{"login-flow", "login", "settings-flow", "settings", "logout"}, f.calls)
	require.Equal(t, "a-brand-new-long-pw", f.settingBody["password"])
	require.Equal(t, "password", f.settingBody["method"])
	require.Equal(t, fakeToken, f.settingAuth, "the settings flow runs on the check's own session")
	require.Equal(t, fakeToken, f.logoutBody["session_token"], "the check's session is ended")
}

func TestChangePassword_AWrongCurrentPasswordStopsBeforeTheChange(t *testing.T) {
	f := &fakePublic{}
	p := newPublic(t, f)

	err := p.ChangePassword(t.Context(), "ada@example.org", "not-it", "a-brand-new-long-pw")

	require.ErrorIs(t, err, kratos.ErrWrongPassword)
	require.Equal(t, []string{"login-flow", "login"}, f.calls, "nothing is changed and there is no session to end")
}

func TestChangePassword_APolicyRefusalIsAWeakPasswordAndStillSignsTheCheckOut(t *testing.T) {
	for _, id := range []int{4000005, 4000031, 4000032, 4000033, 4000034} {
		f := &fakePublic{settingsMessage: id}
		p := newPublic(t, f)

		err := p.ChangePassword(t.Context(), "ada@example.org", fakeCurrent, "short")

		require.ErrorIs(t, err, kratos.ErrWeakPassword, "message %d", id)
		require.Equal(t, "logout", f.calls[len(f.calls)-1], "message %d", id)
	}
}

func TestChangePassword_OtherFailuresAreNeitherWrongNorWeak(t *testing.T) {
	cases := map[string]*fakePublic{
		"flow unavailable":   {flowStatus: 503},
		"login server error": {loginStatus: 500},
		"settings 500":       {settingsStatus: 500},
		"unknown 400":        {settingsMessage: 4999999},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			p := newPublic(t, f)

			err := p.ChangePassword(t.Context(), "ada@example.org", fakeCurrent, "a-brand-new-long-pw")

			require.Error(t, err)
			require.False(t, errors.Is(err, kratos.ErrWrongPassword) || errors.Is(err, kratos.ErrWeakPassword), "%v", err)
			require.NotContains(t, err.Error(), fakeToken)
			require.NotContains(t, err.Error(), fakeCurrent)
		})
	}
}

func TestChangePassword_NeedsAllThreeValues(t *testing.T) {
	p := kratos.NewPublic("http://127.0.0.1:1", time.Second)
	for _, args := range [][3]string{{"", "a", "b"}, {"x", "", "b"}, {"x", "a", ""}} {
		require.Error(t, p.ChangePassword(t.Context(), args[0], args[1], args[2]))
	}
}

func TestChangePassword_AnUnreachableKratosIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	err := kratos.NewPublic(url, 200*time.Millisecond).ChangePassword(t.Context(), "ada@example.org", fakeCurrent, "a-brand-new-long-pw")

	require.Error(t, err)
	require.NotErrorIs(t, err, kratos.ErrWrongPassword)
}
