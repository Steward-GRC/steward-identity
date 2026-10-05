// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package config reads the identity service's settings from the environment.
package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TLS is the server certificate and the CA client certificates must chain
// to. Empty serves plain gRPC.
type TLS struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

// Polis is the SSO broker's admin API.
type Polis struct {
	AdminURL string
	APIKey   string
	Product  string
	// GatewayBaseURL is where Polis sends users back after sign-in.
	GatewayBaseURL string
}

// WebAuthn is the passkey relying party.
type WebAuthn struct {
	RPID             string
	RPOrigins        []string
	RPName           string
	UserVerification string
}

// SPCert is the SAML service-provider signing certificate: its private key
// and the Polis client secrets live in Kubernetes Secrets, never in the
// database.
type SPCert struct {
	SecretName      string
	Namespace       string
	PolisSecretName string
	TTLDays         int
	OverlapHours    int
}

// Config is every setting the service runs with.
type Config struct {
	DatabaseDSN   string
	MigrateDSN    string // a direct connection for migrations; defaults to DatabaseDSN
	MigrationsDir string
	RabbitURL     string
	GRPCPort      string
	// ProbePort serves /livez and /readyz over plain HTTP.
	ProbePort    string
	OTLPEndpoint string

	RedisAddr         string
	RedisPassword     string
	IdpGroupsCacheTTL time.Duration

	TLS TLS
	// TrustedCallers are the SPIFFE IDs whose forwarded actor is believed.
	TrustedCallers []string
	// AdminCLIID is the SPIFFE ID of the admin CLI's client certificate; a
	// call from it may use the admin services.
	AdminCLIID string

	BreakGlassDuration time.Duration

	// KratosAdminURL is the Kratos admin API. Empty turns local accounts and
	// session management off (they answer with coded "unavailable" errors).
	KratosAdminURL string
	KratosSchemaID string
	Polis          Polis

	Login2FAEnabled bool
	// OTPDevEcho logs one-time codes, for local development only.
	OTPDevEcho bool
	TotpEncKey string
	WebAuthn   WebAuthn

	VerifyTXTPrefix       string
	DomainRecheckInterval time.Duration
	SPCert                SPCert

	// CoreGRPCAddr is steward-core, for merge and the delete checks. Empty
	// makes those checks fail closed.
	CoreGRPCAddr string
}

// Load reads the settings through getenv (os.Getenv in production).
func Load(getenv func(string) string) (Config, error) {
	or := func(k, d string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return d
	}
	var errs []error
	duration := func(k, d string) time.Duration {
		v, err := time.ParseDuration(or(k, d))
		if err != nil || v <= 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive duration", k))
		}
		return v
	}
	boolean := func(k string) bool {
		v, err := strconv.ParseBool(or(k, "false"))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s must be true or false", k))
		}
		return v
	}
	integer := func(k string, d int) int {
		v, err := strconv.Atoi(or(k, strconv.Itoa(d)))
		if err != nil || v <= 0 {
			errs = append(errs, fmt.Errorf("%s must be a positive whole number", k))
		}
		return v
	}

	c := Config{
		DatabaseDSN:       getenv("DATABASE_DSN"),
		MigrationsDir:     or("MIGRATIONS_DIR", "migrations"),
		RabbitURL:         getenv("RABBITMQ_URL"),
		GRPCPort:          or("GRPC_PORT", "9090"),
		ProbePort:         or("PROBE_PORT", "8080"),
		OTLPEndpoint:      or("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
		RedisAddr:         getenv("REDIS_ADDR"),
		RedisPassword:     getenv("REDIS_PASSWORD"),
		IdpGroupsCacheTTL: duration("IDP_GROUPS_CACHE_TTL", "1m"),
		TLS: TLS{CertFile: getenv("GRPC_TLS_CERT_FILE"), KeyFile: getenv("GRPC_TLS_KEY_FILE"),
			ClientCAFile: getenv("GRPC_TLS_CLIENT_CA_FILE")},
		TrustedCallers:     list(getenv("IDENTITY_TRUSTED_CALLERS")),
		AdminCLIID:         strings.TrimSpace(getenv("IDENTITY_ADMIN_CLI_ID")),
		BreakGlassDuration: duration("BREAK_GLASS_DURATION", "15m"),
		KratosAdminURL:     getenv("KRATOS_ADMIN_URL"),
		KratosSchemaID:     or("KRATOS_SCHEMA_ID", "default"),
		Polis: Polis{AdminURL: getenv("POLIS_ADMIN_URL"), APIKey: getenv("POLIS_API_KEY"),
			Product: or("POLIS_PRODUCT", "steward"), GatewayBaseURL: or("GATEWAY_BASE_URL", "http://localhost:5173")},
		Login2FAEnabled: boolean("LOGIN_2FA_ENABLED"),
		OTPDevEcho:      boolean("OTP_DEV_ECHO"),
		TotpEncKey:      getenv("TOTP_ENC_KEY"),
		WebAuthn: WebAuthn{RPID: or("WEBAUTHN_RP_ID", "localhost"), RPOrigins: list(or("WEBAUTHN_RP_ORIGINS", "http://localhost:5173")),
			RPName: or("WEBAUTHN_RP_NAME", "Steward"), UserVerification: or("WEBAUTHN_USER_VERIFICATION", "preferred")},
		VerifyTXTPrefix:       or("VERIFY_TXT_PREFIX", "steward-verify"),
		DomainRecheckInterval: duration("DOMAIN_RECHECK_INTERVAL", "6h"),
		SPCert: SPCert{SecretName: or("SP_CERT_SECRET_NAME", "identity-sp-cert"), Namespace: or("SP_CERT_NAMESPACE", getenv("POD_NAMESPACE")),
			PolisSecretName: or("POLIS_SECRET_NAME", "identity-polis-secrets"),
			TTLDays:         integer("SP_CERT_TTL_DAYS", 365), OverlapHours: integer("SP_CERT_OVERLAP_HOURS", 48)},
		CoreGRPCAddr: getenv("CORE_GRPC_ADDR"),
	}
	c.MigrateDSN = or("MIGRATE_DSN", c.DatabaseDSN)

	if c.DatabaseDSN == "" {
		errs = append(errs, errors.New("DATABASE_DSN is required"))
	}
	if c.RabbitURL == "" {
		errs = append(errs, errors.New("RABBITMQ_URL is required"))
	}
	tlsSet := c.TLS.CertFile != "" || c.TLS.KeyFile != "" || c.TLS.ClientCAFile != ""
	if tlsSet && (c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "") {
		errs = append(errs, errors.New("GRPC_TLS_CERT_FILE, GRPC_TLS_KEY_FILE and GRPC_TLS_CLIENT_CA_FILE are set together"))
	}
	if len(c.TrustedCallers) > 0 && !tlsSet {
		errs = append(errs, errors.New("IDENTITY_TRUSTED_CALLERS needs GRPC_TLS_* with client certificates"))
	}
	if c.AdminCLIID != "" && !tlsSet {
		errs = append(errs, errors.New("IDENTITY_ADMIN_CLI_ID needs GRPC_TLS_* with client certificates"))
	}
	return c, errors.Join(errs...)
}

func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
