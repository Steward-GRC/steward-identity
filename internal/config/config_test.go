// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/workloadauth"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const dsn = "postgres://identity@db.example.org/identity"

func base() map[string]string {
	return map[string]string{
		"DATABASE_DSN": dsn, "RABBITMQ_URL": "amqp://mq.example.org",
		"WORKLOAD_OIDC_ISSUER": "https://issuer.example.org", "WORKLOAD_ALLOWED_SERVICEACCOUNTS": "steward/steward-gateway",
	}
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
	require.True(t, c.WorkloadAuthEnabled, "service-to-service authentication is on unless explicitly disabled")
	require.Equal(t, "steward", c.WorkloadAuth.Audience)
	require.Equal(t, workloadauth.DefaultTokenFile, c.TokenFile, "identity sends its own token on its calls to core")
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
	require.Empty(t, c.WorkflowGRPCAddr, "the approval check and the merge fail closed until workflow is configured")
	require.Empty(t, c.ObligationsGRPCAddr, "the merge fails closed until obligations is configured")
}

func TestLoadReadsEverySetting(t *testing.T) {
	m := base()
	for k, v := range map[string]string{
		"MIGRATE_DSN": "postgres://migrate@db.example.org/identity", "MIGRATIONS_DIR": "/migrations", "GRPC_PORT": "9443", "PROBE_PORT": "8081",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "otel.example.org:4317",
		"REDIS_ADDR":                  "cache.example.org:6379", "REDIS_PASSWORD": "pw", "IDP_GROUPS_CACHE_TTL": "2m",
		"GRPC_TLS_CERT_FILE": "/tls/tls.crt", "GRPC_TLS_KEY_FILE": "/tls/tls.key", "GRPC_TLS_CLIENT_CA_FILE": "/tls/ca.crt",
		"WORKLOAD_OIDC_JWKS_URL": "https://issuer.example.org/openid/v1/jwks", "WORKLOAD_OIDC_CA_FILE": "/oidc/ca.crt",
		"WORKLOAD_OIDC_BEARER_FILE": "/oidc/token", "WORKLOAD_AUDIENCE": "steward",
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "steward/steward-gateway, steward/steward-workflow",
		"WORKLOAD_TOKEN_FILE":              "/run/token",
		"IDENTITY_ADMIN_CLI_ID":            "spiffe://example.org/ns/steward/sa/identity-admin",
		"BREAK_GLASS_DURATION":             "30m",
		"KRATOS_ADMIN_URL":                 "http://kratos.example.org:4434", "KRATOS_SCHEMA_ID": "staff",
		"POLIS_ADMIN_URL": "http://polis.example.org:5225", "POLIS_API_KEY": "key", "POLIS_PRODUCT": "acme",
		"GATEWAY_BASE_URL":  "https://policies.example.org",
		"LOGIN_2FA_ENABLED": "true", "OTP_DEV_ECHO": "true", "TOTP_ENC_KEY": "k",
		"WEBAUTHN_RP_ID": "policies.example.org", "WEBAUTHN_RP_ORIGINS": "https://policies.example.org, https://staff.example.org",
		"WEBAUTHN_RP_NAME": "Example", "WEBAUTHN_USER_VERIFICATION": "required",
		"VERIFY_TXT_PREFIX": "example-verify", "DOMAIN_RECHECK_INTERVAL": "1h",
		"SP_CERT_SECRET_NAME": "sp", "SP_CERT_NAMESPACE": "steward", "POLIS_SECRET_NAME": "ps", "SP_CERT_TTL_DAYS": "30", "SP_CERT_OVERLAP_HOURS": "12",
		"CORE_GRPC_ADDR": "core.example.org:9090", "WORKFLOW_GRPC_ADDR": "workflow.example.org:9090",
		"OBLIGATIONS_GRPC_ADDR": "obligations.example.org:9090",
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
	require.Equal(t, workloadauth.Config{
		Issuer: "https://issuer.example.org", JWKSURL: "https://issuer.example.org/openid/v1/jwks", CAFile: "/oidc/ca.crt",
		BearerFile: "/oidc/token", Audience: "steward", AllowedServiceAccounts: []string{"steward/steward-gateway", "steward/steward-workflow"},
	}, c.WorkloadAuth)
	require.Equal(t, "/run/token", c.TokenFile)
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
	require.Equal(t, SPCert{SecretName: "sp", Namespace: "steward", PolisSecretName: "ps", PolisSecretNamespace: "steward", TTLDays: 30, OverlapHours: 12}, c.SPCert)
	require.Equal(t, "core.example.org:9090", c.CoreGRPCAddr)
	require.Equal(t, "workflow.example.org:9090", c.WorkflowGRPCAddr)
	require.Equal(t, "obligations.example.org:9090", c.ObligationsGRPCAddr)
}

func TestLoadNeedsTheDatabaseAndTheBroker(t *testing.T) {
	_, err := Load(env(map[string]string{}))
	require.Error(t, err)
	require.Contains(t, err.Error(), "DATABASE_DSN is required")
	require.Contains(t, err.Error(), "RABBITMQ_URL is required")
}

func TestLoadRejectsBadValues(t *testing.T) {
	for k, v := range map[string]string{
		"IDP_GROUPS_CACHE_TTL":             "soon",
		"BREAK_GLASS_DURATION":             "0s",
		"DOMAIN_RECHECK_INTERVAL":          "-1h",
		"LOGIN_2FA_ENABLED":                "maybe",
		"SP_CERT_TTL_DAYS":                 "x",
		"WORKLOAD_AUTH":                    "off",
		"WORKLOAD_OIDC_ISSUER":             "http://issuer.example.org",
		"WORKLOAD_ALLOWED_SERVICEACCOUNTS": "steward-gateway",
	} {
		m := base()
		m[k] = v
		_, err := Load(env(m))
		require.Error(t, err, k)
		require.Contains(t, err.Error(), k)
	}
}

func TestLoadFailsClosedWithoutWorkloadAuth(t *testing.T) {
	m := base()
	delete(m, "WORKLOAD_OIDC_ISSUER")
	_, err := Load(env(m))
	require.ErrorIs(t, err, workloadauth.ErrNotConfigured, "no issuer and no explicit off switch stops the boot")
}

func TestLoadTurnsWorkloadAuthOffOnlyWhenDisabled(t *testing.T) {
	m := base()
	delete(m, "WORKLOAD_OIDC_ISSUER")
	delete(m, "WORKLOAD_ALLOWED_SERVICEACCOUNTS")
	m["WORKLOAD_AUTH"] = "disabled"
	c, err := Load(env(m))
	require.NoError(t, err)
	require.False(t, c.WorkloadAuthEnabled)
	require.Empty(t, c.TokenFile, "with authentication off identity sends no token")

	m["WORKLOAD_OIDC_ISSUER"] = "https://issuer.example.org"
	_, err = Load(env(m))
	require.Error(t, err, "disabled together with an issuer is a contradiction that stops the boot")
}

func TestTLSIsAllOrNothingAndTheCLINeedsIt(t *testing.T) {
	m := base()
	m["GRPC_TLS_CERT_FILE"] = "/tls/tls.crt"
	_, err := Load(env(m))
	require.ErrorContains(t, err, "set together")

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

func TestLoadSessionLastSeenThrottle(t *testing.T) {
	c, err := Load(env(base()))
	require.NoError(t, err)
	require.Equal(t, time.Minute, c.SessionLastSeenThrottle)

	m := base()
	m["SESSION_LAST_SEEN_THROTTLE"] = "5m"
	c, err = Load(env(m))
	require.NoError(t, err)
	require.Equal(t, 5*time.Minute, c.SessionLastSeenThrottle)

	m["SESSION_LAST_SEEN_THROTTLE"] = "0s"
	_, err = Load(env(m))
	require.ErrorContains(t, err, "SESSION_LAST_SEEN_THROTTLE")
}

func TestLoad_PolisSecretNamespaceStandsAlone(t *testing.T) {
	m := base()
	m["POLIS_SECRET_NAMESPACE"] = "steward-ns"
	c, err := Load(env(m))
	require.NoError(t, err)
	require.Empty(t, c.SPCert.Namespace, "the signing certificate stays off")
	require.Equal(t, "steward-ns", c.SPCert.PolisSecretNamespace)
}
