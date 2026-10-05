// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package readiness_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/readiness"
)

type fakeDB struct{ down atomic.Bool }

func (f *fakeDB) Ping(context.Context) error {
	if f.down.Load() {
		return errors.New("connection refused")
	}
	return nil
}

func (*fakeDB) ServerVersion(context.Context) (string, error) { return "16.4", nil }

type fakeBroker struct{ down atomic.Bool }

func (f *fakeBroker) Healthy() bool { return !f.down.Load() }

// fakeOry serves a health path and a version path, and can be taken down.
func fakeOry(t *testing.T, healthPath, versionPath, version string) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case healthPath, versionPath:
			_, _ = w.Write([]byte(`{"status":"ok","version":"` + version + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &down
}

func checker(t *testing.T, d readiness.Deps) *health.Checker {
	t.Helper()
	c, err := readiness.New(d, health.WithTTL(time.Millisecond), health.WithTimeout(time.Second))
	require.NoError(t, err)
	return c
}

func dep(t *testing.T, r health.Report, name string) health.DependencyReport {
	t.Helper()
	for _, d := range r.Dependencies {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no %q in the report", name)
	return health.DependencyReport{}
}

func names(r health.Report) []string {
	var out []string
	for _, d := range r.Dependencies {
		out = append(out, d.Name)
	}
	return out
}

func TestOnlyPostgresIsRequired(t *testing.T) {
	kratos, _ := fakeOry(t, "/admin/health/ready", "/admin/version", "v1.3.1")
	polis, _ := fakeOry(t, "/api/health", "/api/health", "1.52.0")
	r := checker(t, readiness.Deps{Postgres: &fakeDB{}, Broker: &fakeBroker{},
		Cache: func(context.Context) error { return nil }, KratosAdminURL: kratos.URL, PolisURL: polis.URL}).Report(context.Background())
	require.True(t, r.Ready)
	require.Equal(t, health.StateOK, r.Status)
	require.Equal(t, []string{readiness.Postgres, readiness.RabbitMQ, readiness.Valkey, readiness.Kratos, readiness.Polis}, names(r))
	require.True(t, dep(t, r, readiness.Postgres).Required)
	for _, n := range []string{readiness.RabbitMQ, readiness.Valkey, readiness.Kratos, readiness.Polis} {
		require.False(t, dep(t, r, n).Required, n)
	}
	require.Equal(t, "16.4", dep(t, r, readiness.Postgres).Version)
	require.Equal(t, "v1.3.1", dep(t, r, readiness.Kratos).Version)
	require.Equal(t, "1.52.0", dep(t, r, readiness.Polis).Version)
}

func TestFeaturesThatAreOffAreNotReported(t *testing.T) {
	r := checker(t, readiness.Deps{Postgres: &fakeDB{}, Broker: &fakeBroker{}}).Report(context.Background())
	require.Equal(t, []string{readiness.Postgres, readiness.RabbitMQ}, names(r))
}

func TestPostgresDownMakesIdentityNotReadyAndRecovers(t *testing.T) {
	db := &fakeDB{}
	c := checker(t, readiness.Deps{Postgres: db, Broker: &fakeBroker{}})
	db.down.Store(true)
	require.Eventually(t, func() bool { return !c.Report(context.Background()).Ready }, 2*time.Second, 5*time.Millisecond)
	require.Equal(t, health.StateDown, dep(t, c.Report(context.Background()), readiness.Postgres).State)
	db.down.Store(false)
	require.Eventually(t, func() bool { return c.Report(context.Background()).Ready }, 2*time.Second, 5*time.Millisecond)
}

func TestAnOptionalDependencyDownDegradesButStaysReady(t *testing.T) {
	b := &fakeBroker{}
	var cacheDown atomic.Bool
	kratos, kratosDown := fakeOry(t, "/admin/health/ready", "/admin/version", "v1.3.1")
	polis, polisDown := fakeOry(t, "/api/health", "/api/health", "1.52.0")
	c := checker(t, readiness.Deps{Postgres: &fakeDB{}, Broker: b, KratosAdminURL: kratos.URL, PolisURL: polis.URL,
		Cache: func(context.Context) error {
			if cacheDown.Load() {
				return errors.New("connection refused")
			}
			return nil
		}})
	for name, takeDown := range map[string]func(bool){
		readiness.RabbitMQ: func(v bool) { b.down.Store(v) },
		readiness.Valkey:   cacheDown.Store,
		readiness.Kratos:   kratosDown.Store,
		readiness.Polis:    polisDown.Store,
	} {
		takeDown(true)
		require.Eventually(t, func() bool { return dep(t, c.Report(context.Background()), name).State == health.StateDegraded }, 2*time.Second, 5*time.Millisecond, name)
		r := c.Report(context.Background())
		require.True(t, r.Ready, name+" is optional")
		require.Equal(t, health.StateDegraded, r.Status, name)
		takeDown(false)
		require.Eventually(t, func() bool { return c.Report(context.Background()).Status == health.StateOK }, 2*time.Second, 5*time.Millisecond, name)
	}
}
