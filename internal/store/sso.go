// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SSODomain maps an email domain to how its users sign in: local (a local
// password) or sso (an organisation's IdP connection). ConnectionID is set
// only for method=sso.
type SSODomain struct {
	Domain       string
	Method       string
	ConnectionID *uuid.UUID
	Verified     bool
	VerifiedAt   *time.Time
	CreatedBy    string
	CreatedAt    time.Time
}

// DiscoverResult is the outcome of DiscoverMethod: which method a domain
// should route through, and (only when Method=="sso") the connection alias
// to sign in through.
type DiscoverResult struct {
	Method          string
	ConnectionAlias string
	// IdPInitiatedSSOURL is the connection's IdP-initiated launch URL, read
	// from the connection config key "idpInitiatedSsoUrl". Set only for an
	// ACTIVE method=sso connection that carries one (an IdP app that can't
	// answer an SP-initiated AuthnRequest); empty otherwise. When set, the
	// gateway starts sign-in by redirecting to this URL.
	IdPInitiatedSSOURL string
	// AllowLocal reports that the domain's org opted into local (Kratos)
	// password login as a fallback. Only meaningful when
	// Method=="sso": the login gate may then also offer the local password form.
	AllowLocal bool
}

// IdPConnection is an organisation's SSO connection (SAML or OIDC) brokered
// through Polis. Config holds non-secret settings only; the private
// key/client-secret material lives out-of-band, referenced by SecretRef.
type IdPConnection struct {
	ID              uuid.UUID
	OrgName         string
	Protocol        string
	ConnectionAlias string
	DisplayName     string
	Config          map[string]any
	SecretRef       string
	Enabled         bool
	// JitEnabled controls whether a first-seen SSO user is JIT-provisioned on
	// the SSO callback. Defaults true; when false an unknown SSO
	// email fails closed instead of being auto-created.
	JitEnabled bool
	// AllowLocal permits this org's users to sign in with a local (Kratos)
	// password as a fallback even when the org has an SSO connection
	//. Defaults false (SSO-only).
	AllowLocal   bool
	TestPassedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UpsertSSODomain creates or updates a domain's routing method. The domain
// is stored lower-cased; on conflict, method and connection_id are
// overwritten (verification state is left untouched so re-pointing a
// domain at a new connection doesn't silently re-arm sso for it — callers
// must re-verify).
func (s *Store) UpsertSSODomain(ctx context.Context, d SSODomain) (SSODomain, error) {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sso_domains (domain, method, connection_id, created_by)
		 VALUES (lower($1), $2, $3, $4)
		 ON CONFLICT (domain) DO UPDATE SET method = EXCLUDED.method, connection_id = EXCLUDED.connection_id
		 RETURNING domain, method, connection_id, verified, verified_at, created_by, created_at`,
		d.Domain, d.Method, nullableUUID(d.ConnectionID), d.CreatedBy).
		Scan(&d.Domain, &d.Method, &d.ConnectionID, &d.Verified, &d.VerifiedAt, &d.CreatedBy, &d.CreatedAt)
	if err != nil {
		return SSODomain{}, mapPgError(err, ErrInvalid)
	}
	return d, nil
}

// GetSSODomain loads a single domain's routing configuration.
func (s *Store) GetSSODomain(ctx context.Context, domain string) (SSODomain, error) {
	var d SSODomain
	err := s.pool.QueryRow(ctx,
		`SELECT domain, method, connection_id, verified, verified_at, created_by, created_at
		 FROM sso_domains WHERE domain = lower($1)`, domain).
		Scan(&d.Domain, &d.Method, &d.ConnectionID, &d.Verified, &d.VerifiedAt, &d.CreatedBy, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SSODomain{}, ErrNotFound
	}
	if err != nil {
		return SSODomain{}, err
	}
	return d, nil
}

// ListSSODomains returns every configured domain, ordered by domain name.
func (s *Store) ListSSODomains(ctx context.Context) ([]SSODomain, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT domain, method, connection_id, verified, verified_at, created_by, created_at
		 FROM sso_domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SSODomain{}
	for rows.Next() {
		var d SSODomain
		if err := rows.Scan(&d.Domain, &d.Method, &d.ConnectionID, &d.Verified, &d.VerifiedAt, &d.CreatedBy, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteSSODomain removes a domain's routing configuration.
func (s *Store) DeleteSSODomain(ctx context.Context, domain string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sso_domains WHERE domain = lower($1)`, domain)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkDomainVerified flips a domain's verified gate (domain-ownership proof,
// e.g. DNS TXT record confirmed). This is one of the two gates DiscoverMethod
// requires before routing a method=sso domain to its IdP.
func (s *Store) MarkDomainVerified(ctx context.Context, domain string, at time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sso_domains SET verified = TRUE, verified_at = $2 WHERE domain = lower($1)`, domain, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDomainVerified explicitly sets a domain's verified gate. Setting false
// REVOKES ownership proof (clears verified_at) — used by the periodic re-check
// (RecheckVerifiedDomains) when a previously-confirmed TXT record disappears,
// and by explicit token rotation (which invalidates the prior proof) + a
// protocol change (which resets the org to the start). Setting true mirrors
// MarkDomainVerified. ErrNotFound when the domain isn't registered.
func (s *Store) SetDomainVerified(ctx context.Context, domain string, verified bool) error {
	q := `UPDATE sso_domains SET verified = FALSE, verified_at = NULL WHERE domain = lower($1)`
	if verified {
		q = `UPDATE sso_domains SET verified = TRUE, verified_at = now() WHERE domain = lower($1)`
	}
	tag, err := s.pool.Exec(ctx, q, domain)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DomainVerification is a domain's DNS-TXT (or email) ownership-proof record:
// the token an admin must publish, and — once matched — when it was
// confirmed. It gates one of the two conditions DiscoverMethod requires
// before routing a method=sso domain to its IdP (the other being the
// connection's enabled+test-passed state).
type DomainVerification struct {
	Domain     string
	Token      string
	Method     string
	VerifiedAt *time.Time
}

// CreateDomainVerification mints (or re-mints) the pending verification token
// for a domain. The domain must already exist in sso_domains (FK) — callers
// register it via AddOrganization first, then arm verification. Re-calling
// for an existing domain replaces the token and clears any prior
// verified_at, so restarting verification always requires a fresh proof; a
// stale token can no longer complete one.
func (s *Store) CreateDomainVerification(ctx context.Context, domain, token, method string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO domain_verification (domain, token, method)
		 VALUES (lower($1), $2, $3)
		 ON CONFLICT (domain) DO UPDATE SET token = EXCLUDED.token, method = EXCLUDED.method, verified_at = NULL`,
		domain, token, method)
	if err != nil {
		return mapPgError(err, ErrInvalid)
	}
	return nil
}

// GetDomainVerification loads a domain's pending or completed verification
// record. ErrNotFound when no verification has been started for the domain.
func (s *Store) GetDomainVerification(ctx context.Context, domain string) (DomainVerification, error) {
	var v DomainVerification
	err := s.pool.QueryRow(ctx,
		`SELECT domain, token, method, verified_at FROM domain_verification WHERE domain = lower($1)`, domain).
		Scan(&v.Domain, &v.Token, &v.Method, &v.VerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DomainVerification{}, ErrNotFound
	}
	if err != nil {
		return DomainVerification{}, err
	}
	return v, nil
}

// DiscoverMethod resolves how a domain's users should authenticate. A
// method=sso domain only routes to its IdP once BOTH gates pass: the domain
// is verified AND the connection is enabled with a passed test login;
// otherwise it falls back to local so a half-configured sso domain never
// locks users out or leaks a broken redirect. Non-sso methods pass through
// unchanged. ErrNotFound when the domain isn't configured at all.
func (s *Store) DiscoverMethod(ctx context.Context, domain string) (DiscoverResult, error) {
	var (
		method     string
		alias      *string
		launchURL  *string
		active     bool
		allowLocal bool
	)
	err := s.pool.QueryRow(ctx,
		`SELECT d.method,
		        c.connection_alias,
		        c.config->>'idpInitiatedSsoUrl',
		        (d.verified AND c.enabled AND c.test_passed_at IS NOT NULL) AS active,
		        COALESCE(c.allow_local, false) AS allow_local
		 FROM sso_domains d
		 LEFT JOIN idp_connections c ON c.id = d.connection_id
		 WHERE d.domain = lower($1)`, domain).Scan(&method, &alias, &launchURL, &active, &allowLocal)
	if errors.Is(err, pgx.ErrNoRows) {
		return DiscoverResult{}, ErrNotFound
	}
	if err != nil {
		return DiscoverResult{}, err
	}
	if method == "sso" && active && alias != nil {
		res := DiscoverResult{Method: "sso", ConnectionAlias: *alias, AllowLocal: allowLocal}
		if launchURL != nil {
			res.IdPInitiatedSSOURL = *launchURL
		}
		return res, nil
	}
	if method == "sso" {
		// configured-but-inactive domains must not leak sso; fall back to local.
		return DiscoverResult{Method: "local"}, nil
	}
	return DiscoverResult{Method: method}, nil
}

// HasActiveSSO reports whether at least one sso domain is fully usable right
// now: method=sso AND verified AND its connection enabled AND its connection
// test passed. This is exactly the gate DiscoverMethod applies before routing a
// domain to SSO, evaluated across all domains — so it's true iff some login
// would actually be routed to an IdP. The login UI uses it to enable/disable
// the "Sign in with SSO" affordance. A global boolean: it never names a domain
// or connection, so it leaks nothing about which orgs are onboarded.
func (s *Store) HasActiveSSO(ctx context.Context) (bool, error) {
	var has bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
		     SELECT 1
		     FROM sso_domains d
		     JOIN idp_connections c ON c.id = d.connection_id
		     WHERE d.method = 'sso'
		       AND d.verified
		       AND c.enabled
		       AND c.test_passed_at IS NOT NULL
		 )`).Scan(&has)
	if err != nil {
		return false, err
	}
	return has, nil
}

// CreateIdPConnection registers a new customer IdP connection. It starts
// disabled with no passed test, as required by DiscoverMethod's gating.
func (s *Store) CreateIdPConnection(ctx context.Context, c IdPConnection) (IdPConnection, error) {
	if c.Config == nil {
		c.Config = map[string]any{}
	}
	rawConfig, err := json.Marshal(c.Config)
	if err != nil {
		return IdPConnection{}, fmt.Errorf("marshal config: %w", err)
	}
	err = s.pool.QueryRow(ctx,
		`INSERT INTO idp_connections (org_name, protocol, connection_alias, display_name, config, secret_ref)
		 VALUES ($1,$2,$3,$4,$5::jsonb,$6)
		 RETURNING id, enabled, jit_enabled, allow_local, test_passed_at, created_at, updated_at`,
		c.OrgName, c.Protocol, c.ConnectionAlias, c.DisplayName, rawConfig, c.SecretRef).
		Scan(&c.ID, &c.Enabled, &c.JitEnabled, &c.AllowLocal, &c.TestPassedAt, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return IdPConnection{}, mapPgError(err, ErrConflict)
	}
	return c, nil
}

// UpdateIdPConnectionConfig overwrites a connection's config JSONB. It is used
// after a provisioning backend returns identifiers that must be persisted for a
// later teardown (e.g. the Polis/Jackson clientID/clientSecret + tenant/product),
// which are only known AFTER the connection row was inserted disabled. It never
// touches the connection's enabled / test_passed_at gates. ErrNotFound when no
// such row exists.
func (s *Store) UpdateIdPConnectionConfig(ctx context.Context, id uuid.UUID, config map[string]any) error {
	if config == nil {
		config = map[string]any{}
	}
	rawConfig, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE idp_connections SET config=$2::jsonb, updated_at=now() WHERE id=$1`,
		id, rawConfig)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteIdPConnection removes a customer IdP connection by id. It is the
// compensating action AddOrganization runs when Polis provisioning fails
// after the DB row was created, so a failed provision never leaves a
// half-created connection behind. ErrNotFound when no such row exists.
func (s *Store) DeleteIdPConnection(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM idp_connections WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetIdPConnectionEnabled flips the connection's enabled flag — one of the
// two gates DiscoverMethod requires before routing to it.
func (s *Store) SetIdPConnectionEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE idp_connections SET enabled=$2, updated_at=now() WHERE id=$1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetIdPConnectionLoginToggles updates the per-org login toggles jit_enabled
// and allow_local. A nil argument leaves that
// toggle unchanged (COALESCE keeps the stored value), so an admin can flip one
// without touching the other or resupplying the connection config. ErrNotFound
// when no such row exists.
func (s *Store) SetIdPConnectionLoginToggles(ctx context.Context, id uuid.UUID, jitEnabled, allowLocal *bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE idp_connections
		 SET jit_enabled = COALESCE($2, jit_enabled),
		     allow_local = COALESCE($3, allow_local),
		     updated_at  = now()
		 WHERE id = $1`, id, jitEnabled, allowLocal)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkIdPTestPassed records a successful admin test login — the other gate
// DiscoverMethod requires before routing to a connection.
func (s *Store) MarkIdPTestPassed(ctx context.Context, id uuid.UUID, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE idp_connections SET test_passed_at=$2, updated_at=now() WHERE id=$1`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearIdPTestPassed drops the connection's passed-test gate (test_passed_at →
// NULL), forcing a fresh admin IdP test before the org can be re-activated. It
// is the inverse of MarkIdPTestPassed, used by ChangeOrgProtocol when a
// protocol switch resets the connection to the start. ErrNotFound when no such
// row exists.
func (s *Store) ClearIdPTestPassed(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `UPDATE idp_connections SET test_passed_at=NULL, updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateIdPConnectionProtocol switches a connection's protocol (oidc<->saml)
// and overwrites its non-secret config + secret_ref for the new protocol. The
// protocol value is validated by the caller (and the idp_connections CHECK
// constraint enforces oidc|saml). It never touches the enabled / test_passed_at
// gates — ChangeOrgProtocol resets those separately. ErrNotFound when no such
// row exists.
func (s *Store) UpdateIdPConnectionProtocol(ctx context.Context, id uuid.UUID, protocol string, config map[string]any, secretRef string) error {
	if config == nil {
		config = map[string]any{}
	}
	rawConfig, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE idp_connections SET protocol=$2, config=$3::jsonb, secret_ref=$4, updated_at=now() WHERE id=$1`,
		id, protocol, rawConfig, secretRef)
	if err != nil {
		return mapPgError(err, ErrInvalid)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
