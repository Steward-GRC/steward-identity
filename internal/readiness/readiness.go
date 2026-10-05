// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package readiness registers identity's dependencies with go-buildinfo's
// health checker. Only Postgres is required: without it identity can answer
// nothing. The rest are optional, so an outage degrades identity instead of
// draining it: audit events wait in the outbox while RabbitMQ is down, the
// group cache falls back to Postgres, and only local accounts, sessions and
// SSO setup need Kratos and Polis.
package readiness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	postgres "github.com/Bugs5382/go-postgres"
)

// Dependency names, as they appear in the report and the
// steward-depstate-<name> headers.
const (
	Postgres = "postgres"
	RabbitMQ = "rabbitmq"
	Valkey   = "valkey"
	Kratos   = "kratos"
	Polis    = "polis"
)

// Database is the Postgres the service runs on.
type Database interface {
	Ping(ctx context.Context) error
	ServerVersion(ctx context.Context) (string, error)
}

// Broker is the RabbitMQ connection; go-rabbitmq's Conn reports it.
type Broker interface{ Healthy() bool }

// Deps are the dependencies to report. A nil Cache or an empty URL is a
// feature that is off, and is not reported.
type Deps struct {
	Postgres       Database
	Broker         Broker
	Cache          func(ctx context.Context) error
	KratosAdminURL string
	PolisURL       string
	// HTTPClient probes Kratos and Polis; nil uses a short-timeout client.
	HTTPClient *http.Client
}

var errBrokerDown = errors.New("rabbitmq connection is down")

// New returns a checker with deps registered.
func New(d Deps, opts ...health.Option) (*health.Checker, error) {
	hc := d.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Second}
	}
	deps := []health.Dependency{
		{Name: Postgres, Required: true, Check: d.Postgres.Ping, Version: d.Postgres.ServerVersion},
		{Name: RabbitMQ, Check: func(context.Context) error {
			if !d.Broker.Healthy() {
				return errBrokerDown
			}
			return nil
		}},
	}
	if d.Cache != nil {
		deps = append(deps, health.Dependency{Name: Valkey, Check: d.Cache})
	}
	if d.KratosAdminURL != "" {
		base := strings.TrimRight(d.KratosAdminURL, "/")
		deps = append(deps, health.Dependency{Name: Kratos,
			Check: health.CheckHTTP(hc, base+"/admin/health/ready"), Version: jsonVersion(hc, base+"/admin/version")})
	}
	if d.PolisURL != "" {
		u := strings.TrimRight(d.PolisURL, "/") + "/api/health"
		deps = append(deps, health.Dependency{Name: Polis, Check: health.CheckHTTP(hc, u), Version: jsonVersion(hc, u)})
	}
	c := health.New(opts...)
	return c, c.Register(deps...)
}

// jsonVersion reads the "version" field both Kratos and Polis answer with.
func jsonVersion(hc *http.Client, url string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		res, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusOK {
			return "", fmt.Errorf("version: status %d", res.StatusCode)
		}
		var body struct {
			Version string `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			return "", err
		}
		return body.Version, nil
	}
}

// PostgresDB adapts go-postgres's DB.
func PostgresDB(db *postgres.DB) Database { return pgDB{db} }

type pgDB struct{ db *postgres.DB }

func (p pgDB) Ping(ctx context.Context) error { return p.db.Ping(ctx) }

// ServerVersion drops the build suffix ("16.4 (Debian 16.4-1)"), which the
// header would redact.
func (p pgDB) ServerVersion(ctx context.Context) (string, error) {
	var v string
	if err := p.db.Pool().QueryRow(ctx, "SHOW server_version").Scan(&v); err != nil {
		return "", err
	}
	if f := strings.Fields(v); len(f) > 0 {
		return f[0], nil
	}
	return v, nil
}
