// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const dsn = "postgres://identity@db.example.org/identity"

func base() map[string]string {
	return map[string]string{"DATABASE_DSN": dsn, "RABBITMQ_URL": "amqp://mq.example.org"}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(base()))
	require.NoError(t, err)
	require.Equal(t, "9090", c.GRPCPort)
	require.Equal(t, "8080", c.ProbePort)
	require.Equal(t, "localhost:4317", c.OTLPEndpoint)
	require.Equal(t, "migrations", c.MigrationsDir)
	require.Equal(t, dsn, c.MigrateDSN)
	require.Empty(t, c.RedisAddr, "the cache is off unless configured")
	require.Equal(t, time.Minute, c.IdpGroupsCacheTTL)
	require.Empty(t, c.TrustedCallers, "no caller is trusted to forward an actor by default")
	require.Empty(t, c.AdminCLIID, "the admin CLI has no access by default")
	require.Equal(t, 15*time.Minute, c.BreakGlassDuration)
	require.Empty(t, c.KratosAdminURL, "local accounts and sessions are off unless Kratos is configured")
	require.Equal(t, "default", c.KratosSchemaID)
	require.Empty(t, c.Polis.AdminURL)
	require.Equal(t, "steward", c.Polis.Product)
	require.False(t, c.Login2FAEnabled)
	require.False(t, c.OTPDevEcho, "codes are never logged unless asked for")
	require.Equal(t, "localhost", c.WebAuthn.RPID)
	require.Equal(t, []string{"http://localhost:5173"}, c.WebAuthn.RPOrigins)
	require.Equal(t, "Steward", c.WebAuthn.RPName)
	require.Equal(t, "preferred", c.WebAuthn.UserVerification)
	require.Equal(t, "steward-verify", c.VerifyTXTPrefix)
	require.Equal(t, 6*time.Hour, c.DomainRecheckInterval)
	require.Equal(t, "identity-sp-cert", c.SPCert.SecretName)
	require.Equal(t, "identity-polis-secrets", c.SPCert.PolisSecretName)
	require.Equal(t, 365, c.SPCert.TTLDays)
	require.Equal(t, 48, c.SPCert.OverlapHours)
	require.Empty(t, c.CoreGRPCAddr, "the core checks fail closed until core is configured")
}

func TestLoadReadsEverySetting(t *testing.T) {
	m := base()
	for k, v := range map[string]string{
		"MIGRATE_DSN": "postgres://migrate@db.example.org/identity", "MIGRATIONS_DIR": "/migrations", "GRPC_PORT": "9443", "PROBE_PORT": "8081",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "otel.example.org:4317",
		"REDIS_ADDR":                  "cache.example.org:6379", "REDIS_PASSWORD": "pw", "IDP_GROUPS_CACHE_TTL": "2m",
		"GRPC_TLS_CERT_FILE": "/tls/tls.crt", "GRPC_TLS_KEY_FILE": "/tls/tls.key", "GRPC_TLS_CLIENT_CA_FILE": "/tls/ca.crt",
		"IDENTITY_TRUSTED_CALLERS": "spiffe://example.org/ns/steward/sa/gateway, spiffe://example.org/ns/steward/sa/workflow",
		"IDENTITY_ADMIN_CLI_ID":    "spiffe://example.org/ns/steward/sa/identity-admin",
		"BREAK_GLASS_DURATION":     "30m",
		"KRATOS_ADMIN_URL":         "http://kratos.example.org:4434", "KRATOS_SCHEMA_ID": "staff",
		"POLIS_ADMIN_URL": "http://polis.example.org:5225", "POLIS_API_KEY": "key", "POLIS_PRODUCT": "acme",
		"GATEWAY_BASE_URL":  "https://policies.example.org",
		"LOGIN_2FA_ENABLED": "true", "OTP_DEV_ECHO": "true", "TOTP_ENC_KEY": "k",
		"WEBAUTHN_RP_ID": "policies.example.org", "WEBAUTHN_RP_ORIGINS": "https://policies.example.org, https://staff.example.org",
		"WEBAUTHN_RP_NAME": "Example", "WEBAUTHN_USER_VERIFICATION": "required",
		"VERIFY_TXT_PREFIX": "example-verify", "DOMAIN_RECHECK_INTERVAL": "1h",
		"SP_CERT_SECRET_NAME": "sp", "SP_CERT_NAMESPACE": "steward", "POLIS_SECRET_NAME": "ps", "SP_CERT_TTL_DAYS": "30", "SP_CERT_OVERLAP_HOURS": "12",
		"CORE_GRPC_ADDR": "core.example.org:9090",
	} {
		m[k] = v
	}
	c, err := Load(env(m))
	require.NoError(t, err)
	require.Equal(t, "postgres://migrate@db.example.org/identity", c.MigrateDSN)
	require.Equal(t, "/migrations", c.MigrationsDir)
	require.Equal(t, "9443", c.GRPCPort)
	require.Equal(t, "8081", c.ProbePort)
	require.Equal(t, "cache.example.org:6379", c.RedisAddr)
	require.Equal(t, 2*time.Minute, c.IdpGroupsCacheTTL)
	require.Equal(t, TLS{CertFile: "/tls/tls.crt", KeyFile: "/tls/tls.key", ClientCAFile: "/tls/ca.crt"}, c.TLS)
	require.Equal(t, []string{"spiffe://example.org/ns/steward/sa/gateway", "spiffe://example.org/ns/steward/sa/workflow"}, c.TrustedCallers)
	require.Equal(t, "spiffe://example.org/ns/steward/sa/identity-admin", c.AdminCLIID)
	require.Equal(t, 30*time.Minute, c.BreakGlassDuration)
	require.Equal(t, "http://kratos.example.org:4434", c.KratosAdminURL)
	require.Equal(t, "staff", c.KratosSchemaID)
	require.Equal(t, Polis{AdminURL: "http://polis.example.org:5225", APIKey: "key", Product: "acme", GatewayBaseURL: "https://policies.example.org"}, c.Polis)
	require.True(t, c.Login2FAEnabled)
	require.True(t, c.OTPDevEcho)
	require.Equal(t, "k", c.TotpEncKey)
	require.Equal(t, WebAuthn{RPID: "policies.example.org", RPOrigins: []string{"https://policies.example.org", "https://staff.example.org"},
		RPName: "Example", UserVerification: "required"}, c.WebAuthn)
	require.Equal(t, "example-verify", c.VerifyTXTPrefix)
	require.Equal(t, time.Hour, c.DomainRecheckInterval)
	require.Equal(t, SPCert{SecretName: "sp", Namespace: "steward", PolisSecretName: "ps", TTLDays: 30, OverlapHours: 12}, c.SPCert)
	require.Equal(t, "core.example.org:9090", c.CoreGRPCAddr)
}

func TestLoadNeedsTheDatabaseAndTheBroker(t *testing.T) {
	_, err := Load(env(map[string]string{}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "DATABASE_DSN is required")
	require.Contains(t, err.Error(), "RABBITMQ_URL is required")
}

func TestLoadRejectsBadValues(t *testing.T) {
	for k, v := range map[string]string{
		"IDP_GROUPS_CACHE_TTL":    "soon",
		"BREAK_GLASS_DURATION":    "0s",
		"DOMAIN_RECHECK_INTERVAL": "-1h",
		"LOGIN_2FA_ENABLED":       "maybe",
		"SP_CERT_TTL_DAYS":        "x",
	} {
		m := base()
		m[k] = v
		_, err := Load(env(m))
		require.Error(t, err, k)
		require.Contains(t, err.Error(), k)
	}
}

func TestTLSIsAllOrNothingAndTrustNeedsIt(t *testing.T) {
	m := base()
	m["GRPC_TLS_CERT_FILE"] = "/tls/tls.crt"
	_, err := Load(env(m))
	require.ErrorContains(t, err, "set together")

	m = base()
	m["IDENTITY_TRUSTED_CALLERS"] = "spiffe://example.org/ns/steward/sa/gateway"
	_, err = Load(env(m))
	require.ErrorContains(t, err, "IDENTITY_TRUSTED_CALLERS needs GRPC_TLS_*")

	m = base()
	m["IDENTITY_ADMIN_CLI_ID"] = "spiffe://example.org/ns/steward/sa/identity-admin"
	_, err = Load(env(m))
	require.ErrorContains(t, err, "IDENTITY_ADMIN_CLI_ID needs GRPC_TLS_*")
}

func TestNoSecretInTheError(t *testing.T) {
	m := base()
	m["GRPC_TLS_CERT_FILE"] = "/tls/tls.crt"
	_, err := Load(env(m))
	require.False(t, strings.Contains(err.Error(), dsn), "settings values never appear in errors")
}
