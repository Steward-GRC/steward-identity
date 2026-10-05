// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/sso/polis"
	"github.com/Steward-GRC/steward-identity/internal/sso/spkeys"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// eventSSOOrgAdded is the lifecycle event name emitted when an org's SSO
// connection is created (still disabled). Downstream consumers can surface the
// pending onboarding without polling.
const eventSSOOrgAdded = "sso.org_added"

// eventSSODomainVerificationRequested / eventSSODomainVerified are the
// lifecycle event names for the two DNS-TXT domain-verification events
// . The welcome/notification email templates that consume these are
// the obligations service's job; identity only emits the events.
const (
	eventSSODomainVerificationRequested = "sso.domain_verification_requested"
	eventSSODomainVerified              = "sso.domain_verified"
	// eventSSODomainVerificationRevoked fires when a domain that was verified
	// loses its proof: the periodic re-check (RecheckVerifiedDomains) finds the
	// TXT record gone, or an admin explicitly rotates the token. The domain is
	// flipped back to needs-reverification.
	eventSSODomainVerificationRevoked = "sso.domain_verification_revoked"
)

// defaultVerifyTXTPrefix is the fallback DNS-TXT verification prefix used
// when the handler isn't given an override via WithVerifyTXTPrefix. It backs
// BOTH the record name (_<prefix>.<domain>) and the record value
// (<prefix>=<token>) — see config.Config.VerifyTXTPrefix, which is the
// production source of this value.
const defaultVerifyTXTPrefix = "steward-verify"

// txtLookup resolves a domain's TXT records. It exists so VerifyDomain's DNS
// dependency is swappable in tests (SetTXTLookup) instead of hitting real DNS;
// production wires multiResolverTXTLookup (see NewSSOAdminHandler).
type txtLookup func(ctx context.Context, name string) ([]string, error)

// publicTXTServers are the public DNS resolvers domain-ownership verification
// queries DIRECTLY. A customer's verification TXT record lives on PUBLIC DNS, so
// we must not depend on the pod's cluster/internal resolver (authoritative for
// internal zones, and the wrong tool for an external customer domain).
var publicTXTServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// publicResolverLookup builds a txtLookup that resolves via a specific DNS
// server address, bypassing the pod's /etc/resolv.conf (cluster DNS).
func publicResolverLookup(serverAddr string) txtLookup {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", serverAddr)
		},
	}
	return r.LookupTXT
}

// mergeTXTLookups queries every lookup for name and returns the UNION of the
// records any of them found. It errors ONLY when every lookup failed, so one
// resolver's NXDOMAIN/timeout never masks another resolver's hit.
func mergeTXTLookups(ctx context.Context, name string, lookups ...txtLookup) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	var lastErr error
	anyOK := false
	for _, lk := range lookups {
		recs, err := lk(ctx, name)
		if err != nil {
			lastErr = err
			continue
		}
		anyOK = true
		for _, r := range recs {
			if _, dup := seen[r]; !dup {
				seen[r] = struct{}{}
				out = append(out, r)
			}
		}
	}
	if !anyOK {
		return nil, lastErr
	}
	return out, nil
}

// multiResolverTXTLookup is the production txtLookup: it checks the public DNS
// providers (publicTXTServers) AND the pod's default resolver, accepting a match
// from ANY. Public providers see a customer's public record regardless of
// cluster DNS; the default resolver still resolves internal-only domains.
func multiResolverTXTLookup(ctx context.Context, name string) ([]string, error) {
	lookups := make([]txtLookup, 0, len(publicTXTServers)+1)
	for _, addr := range publicTXTServers {
		lookups = append(lookups, publicResolverLookup(addr))
	}
	lookups = append(lookups, net.DefaultResolver.LookupTXT)
	return mergeTXTLookups(ctx, name, lookups...)
}

// SSOAdminHandler implements IdentitySSOAdminService.
type SSOAdminHandler struct {
	identityv1.UnimplementedIdentitySSOAdminServiceServer
	store           *store.Store
	prov            ssoProvisioner // SSO backend seam (Polis)
	auth            *AdminAuth
	events          ssoEventPublisher // nil → emission skipped
	verifyTXTPrefix string            // DNS-TXT verification prefix; default "steward-verify"
	txtLookup       txtLookup         // DNS-TXT resolver; default net.DefaultResolver.LookupTXT
	sp              *spCertService    // SP-certificate service; nil when spCert.enabled=false (default) — see WithSPCert
	// polisSecrets holds Polis client secrets out-of-band from the
	// database. nil → the indirection is unavailable (local dev,
	// or no in-cluster config), in which case no secret is stored and backend
	// teardown addresses the connection by tenant/product instead.
	polisSecrets spkeys.Store
}

// ssoProvisioner creates and deletes connections in the SSO broker;
// *polis.Client implements it. CreateConnection is all or nothing.
type ssoProvisioner interface {
	CreateConnection(ctx context.Context, spec polis.ConnectionSpec) (polis.ConnectionResult, error)
	DeleteConnection(ctx context.Context, ref polis.ConnectionRef) error
}

// NewSSOAdminHandler returns an SSOAdminHandler that provisions customer SSO
// connections through prov, gated by the given AdminAuth.
func NewSSOAdminHandler(s *store.Store, prov ssoProvisioner, auth *AdminAuth) *SSOAdminHandler {
	return &SSOAdminHandler{
		store:           s,
		prov:            prov,
		auth:            auth,
		verifyTXTPrefix: defaultVerifyTXTPrefix,
		txtLookup:       multiResolverTXTLookup,
	}
}

// WithSSOEventPublisher wires the event seam so SSO lifecycle mutations emit
// events. Nil skips emission; returns the handler for chaining.
func (h *SSOAdminHandler) WithSSOEventPublisher(p ssoEventPublisher) *SSOAdminHandler {
	h.events = p
	return h
}

// WithVerifyTXTPrefix overrides the DNS-TXT verification prefix (default
// "steward-verify") used for both the record name (_<prefix>.<domain>) and
// record value (<prefix>=<token>). Wired from config.Config.VerifyTXTPrefix,
// which always has a default, so an empty prefix here is a no-op rather than
// disabling verification. Returns the handler for chaining.
func (h *SSOAdminHandler) WithVerifyTXTPrefix(prefix string) *SSOAdminHandler {
	if prefix != "" {
		h.verifyTXTPrefix = prefix
	}
	return h
}

// SetTXTLookup swaps the DNS-TXT resolver VerifyDomain calls. It is a test
// seam only — production never calls this, relying on the
// net.DefaultResolver.LookupTXT default wired in NewSSOAdminHandler.
func (h *SSOAdminHandler) SetTXTLookup(fn txtLookup) {
	h.txtLookup = fn
}

// WithSPCert wires the platform SP-certificate service, enabling the three
// SP-certificate admin RPCs (GetSPCertificate, ListSPCertificates,
// ForceRotateSPCertificate). Nil (the default — spCert.enabled=false) leaves
// them disabled; see requireSPCert. Returns the handler for chaining.
func (h *SSOAdminHandler) WithSPCert(sp *spCertService) *SSOAdminHandler {
	h.sp = sp
	return h
}

// WithPolisSecrets wires the out-of-band store that holds Polis client
// secrets, keeping them out of the plaintext idp_connections.config column
// . Wiring is optional and best-effort, exactly like WithSPCert:
// a nil store leaves the indirection disabled, provisioning still succeeds, and
// backend teardown falls back to addressing the connection by tenant/product.
// Returns the handler for chaining.
func (h *SSOAdminHandler) WithPolisSecrets(st spkeys.Store) *SSOAdminHandler {
	h.polisSecrets = st
	return h
}

// persistPolisSecret writes a backend-issued Polis client secret to the
// out-of-band store and returns the reference to persist on config. It returns
// "" when there is nothing to store or no store is wired, in which case no
// reference is recorded and teardown uses tenant/product.
//
// A failure here is logged and swallowed rather than failing provisioning: the
// secret only adds precision to a best-effort teardown, so losing it must not
// cost the caller a working SSO connection. It NEVER logs the secret value.
func (h *SSOAdminHandler) persistPolisSecret(ctx context.Context, connectionID, secret string) string {
	if secret == "" || h.polisSecrets == nil {
		return ""
	}
	ref := polis.PolisClientSecretRef(connectionID)
	if err := h.polisSecrets.PutKey(ctx, ref, []byte(secret)); err != nil {
		lg := log.Ctx(ctx)
		lg.Warn().Err(err).Str("connection_id", connectionID).
			Msg("sso: could not store polis client secret out-of-band; teardown will address by tenant/product")
		return ""
	}
	return ref
}

// resolvePolisSecret reads a connection's Polis client secret back from the
// out-of-band store using the reference on its config. It returns "" whenever
// the secret cannot be resolved — no reference (a pre-#47 row whose plaintext
// was stripped by migration 0012, or a connection provisioned while the store
// was unwired), no store, or a store error. "" is safe: DeleteConnection then
// addresses the Polis connection by tenant/product, which is always
// populated. It NEVER logs the resolved value.
func (h *SSOAdminHandler) resolvePolisSecret(ctx context.Context, conn store.IdPConnection) string {
	ref := configString(conn.Config, polis.ConfigKeyPolisClientSecretRef)
	if ref == "" || h.polisSecrets == nil {
		return ""
	}
	b, err := h.polisSecrets.GetKey(ctx, ref)
	if err != nil {
		lg := log.Ctx(ctx)
		lg.Warn().Err(err).Str("connection_id", conn.ID.String()).
			Msg("sso: could not resolve polis client secret; teardown will address by tenant/product")
		return ""
	}
	return string(b)
}

// requireSPCert returns a clean Unavailable error when the SP-certificate
// service isn't wired (the config-gated default), so the three SP-cert RPCs
// never panic on a nil h.sp.
func (h *SSOAdminHandler) requireSPCert() error {
	if h.sp == nil {
		return status.Error(codes.Unavailable, "sp certificate service not enabled")
	}
	return nil
}

// AddOrganization registers a customer SSO organization: it creates the IdP
// connection DISABLED, provisions the matching backend connection, and only
// then registers the SSO domain. Provisioning is transactional across the DB
// and the backend: if the backend fails, the freshly-created DB row is deleted
// (compensating action) and NO domain is registered, so a failed provision can
// never leave a domain routing to sso. Activation (verify + enable + test) is
// gated by later tasks — the connection stays disabled here.
func (h *SSOAdminHandler) AddOrganization(ctx context.Context, req *identityv1.AddOrganizationRequest) (*identityv1.AddOrganizationResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	orgName := strings.TrimSpace(req.GetOrgName())
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	protocol := strings.ToLower(strings.TrimSpace(req.GetProtocol()))
	if orgName == "" || domain == "" {
		return nil, status.Error(codes.InvalidArgument, "org_name and domain required")
	}
	if protocol != "oidc" && protocol != "saml" {
		return nil, status.Error(codes.InvalidArgument, "protocol must be oidc or saml")
	}

	alias := connectionAlias(orgName, domain)
	reqCfg := req.GetConfig()

	// 1. Create the connection DISABLED (the store enforces enabled=false). The
	// config JSONB starts as the raw (non-secret) wizard settings; a provisioning
	// backend that mints teardown identifiers (Polis) has them merged in
	// after it provisions (step 3).
	conn, err := h.store.CreateIdPConnection(ctx, store.IdPConnection{
		OrgName:         orgName,
		Protocol:        protocol,
		ConnectionAlias: alias,
		DisplayName:     req.GetDisplayName(),
		Config:          stringMapToAny(reqCfg),
		SecretRef:       req.GetSecretRef(),
	})
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	// 2. Provision the SSO connection in the backend. CreateConnection is
	// all-or-nothing: on error
	// nothing was created, so the only cleanup needed is the compensating DB
	// delete — a failed provision can never leave a domain routing to sso, since
	// no domain is registered until step 4.
	result, provErr := h.prov.CreateConnection(ctx, polis.ConnectionSpec{
		Alias:       alias,
		DisplayName: req.GetDisplayName(),
		Protocol:    protocol,
		Domain:      domain,
		SecretRef:   req.GetSecretRef(),
		Config:      reqCfg,
	})
	if provErr != nil {
		// Compensating rollback: delete the DB row so we never half-create. If the
		// delete itself fails we still return the provisioning error; the row is
		// left disabled (never routing to sso, since no domain was registered).
		if delErr := h.store.DeleteIdPConnection(ctx, conn.ID); delErr != nil {
			lg := log.Ctx(ctx)
			lg.Error().Err(delErr).
				Str("connection_id", conn.ID.String()).Str("connection_alias", alias).
				Msg("sso: compensating delete failed after provisioning error; row left disabled")
		}
		// Keep the raw provisioning cause in the logs (debug-only, never on the
		// wire); the client gets the stable coded ErrorInfo (KC_ADMIN_UNREACHABLE
		// / Code 5001) + a user-safe message the gateway relays verbatim.
		dbg := log.Ctx(ctx)
		dbg.Debug().Err(provErr).
			Str("connection_alias", alias).Str("org", orgName).
			Msg("sso: backend provisioning failed")
		return nil, errcodes.Error(ctx, errcodes.SSOProviderUnreachable(orgName, provErr))
	}

	// 3. Persist any backend-issued teardown identifiers (Polis
	// clientID/clientSecret + tenant/product) onto the connection's config so
	// DeleteOrganization can address the backend connection later. If persisting
	// fails after a successful provision, tear the backend connection back down
	// (best-effort) and compensating-delete the DB row so we never orphan an
	// un-addressable backend connection.
	//: the client secret goes to the out-of-band store FIRST, so a
	// crash between the two writes leaves either (no secret, no ref) or
	// (secret, no ref) — both safe, both degrading to tenant/product teardown.
	// Only the non-secret reference is merged into the plaintext config column.
	secretRef := h.persistPolisSecret(ctx, conn.ID.String(), result.ClientSecret)
	if extra := result.ConfigKeys(); len(extra) > 0 || secretRef != "" {
		merged := stringMapToAny(reqCfg)
		if merged == nil {
			merged = map[string]any{}
		}
		maps.Copy(merged, extra)
		if secretRef != "" {
			merged[polis.ConfigKeyPolisClientSecretRef] = secretRef
		}
		if err := h.store.UpdateIdPConnectionConfig(ctx, conn.ID, merged); err != nil {
			lg := log.Ctx(ctx)
			if delErr := h.prov.DeleteConnection(ctx, polis.ConnectionRef{
				Domain:       domain,
				ClientID:     result.ClientID,
				ClientSecret: result.ClientSecret,
				Tenant:       result.Tenant,
				Product:      result.Product,
			}); delErr != nil {
				lg.Error().Err(delErr).Str("connection_id", conn.ID.String()).
					Msg("sso: backend teardown failed after config-persist error; connection may be orphaned")
			}
			if delErr := h.store.DeleteIdPConnection(ctx, conn.ID); delErr != nil {
				lg.Error().Err(delErr).Str("connection_id", conn.ID.String()).
					Msg("sso: compensating delete failed after config-persist error; row left disabled")
			}
			return nil, status.Errorf(codes.Internal, "persist sso connection identifiers: %v", err)
		}
		conn.Config = merged
	}

	// 4. Register the SSO domain (method=sso) now that both sides are created.
	connID := conn.ID
	if _, err := h.store.UpsertSSODomain(ctx, store.SSODomain{
		Domain:       domain,
		Method:       "sso",
		ConnectionID: &connID,
		CreatedBy:    actorLabel(actor),
	}); err != nil {
		return nil, statusFromStoreErr(err)
	}

	h.emitSSOOrgAdded(ctx, conn, domain)

	return &identityv1.AddOrganizationResponse{Organization: orgToProto(conn, domain, false)}, nil
}

// emitSSOOrgAdded publishes one sso.org_added lifecycle event carrying the org
// vars a template needs. Best-effort via emitSSOEvent.
func (h *SSOAdminHandler) emitSSOOrgAdded(ctx context.Context, conn store.IdPConnection, domain string) {
	emitSSOEvent(ctx, h.events, eventSSOOrgAdded, map[string]any{
		"domain":          domain,
		"orgName":         conn.OrgName,
		"protocol":        conn.Protocol,
		"connectionAlias": conn.ConnectionAlias,
		"connectionId":    conn.ID.String(),
	})
}

// ListOrganizations enumerates every registered SSO organization — one entry
// per method=sso domain that has a connection registered. A domain whose
// connection lookup fails (e.g. a dangling connection_id) is logged and
// skipped rather than failing the whole listing, since the Organizations page
// must still be able to show every other, healthy org.
func (h *SSOAdminHandler) ListOrganizations(ctx context.Context, _ *identityv1.ListOrganizationsRequest) (*identityv1.ListOrganizationsResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domains, err := h.store.ListSSODomains(ctx)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	lg := log.Ctx(ctx)
	out := make([]*identityv1.Organization, 0, len(domains))
	for _, d := range domains {
		if d.ConnectionID == nil {
			// Not an sso-method domain (local/ad) — no organization to report.
			continue
		}
		conn, err := h.store.GetIdPConnection(ctx, *d.ConnectionID)
		if err != nil {
			lg.Warn().Err(err).Str("domain", d.Domain).Str("connection_id", d.ConnectionID.String()).
				Msg("sso: list organizations skipping domain with unresolvable connection")
			continue
		}
		out = append(out, orgToProto(conn, d.Domain, d.Verified))
	}
	return &identityv1.ListOrganizationsResponse{Organizations: out}, nil
}

// GetOrganization loads a single organization by domain. NotFound when the
// domain isn't registered at all; FailedPrecondition (mirroring
// Activate/DisableOrganization) when the domain exists but has no sso
// connection registered — there is no organization to return for it.
func (h *SSOAdminHandler) GetOrganization(ctx context.Context, req *identityv1.GetOrganizationRequest) (*identityv1.GetOrganizationResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	d, err := h.store.GetSSODomain(ctx, domain)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if d.ConnectionID == nil {
		return nil, status.Error(codes.FailedPrecondition, "domain has no sso connection registered")
	}
	conn, err := h.store.GetIdPConnection(ctx, *d.ConnectionID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.GetOrganizationResponse{Organization: orgToProto(conn, domain, d.Verified)}, nil
}

// UpdateIdPConnection updates an org's IdP connection: the per-org login
// toggles jit_enabled and allow_local and, when
// supplied, the connection's non-secret config. Both toggles are `optional` on
// the wire, so an absent toggle leaves the stored value untouched — the admin
// wizard flips one switch at a time. An empty config map likewise leaves config
// as-is (secret_ref rotation is not handled here — it stays a separate flow).
// NotFound when the domain isn't registered; FailedPrecondition when it has no
// sso connection.
func (h *SSOAdminHandler) UpdateIdPConnection(ctx context.Context, req *identityv1.UpdateIdPConnectionRequest) (*identityv1.UpdateIdPConnectionResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	d, err := h.store.GetSSODomain(ctx, domain)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if d.ConnectionID == nil {
		return nil, status.Error(codes.FailedPrecondition, "domain has no sso connection registered")
	}
	conn, err := h.store.GetIdPConnection(ctx, *d.ConnectionID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	// Per-org login toggles: a nil pointer leaves that toggle unchanged (the
	// store COALESCEs it against the stored value).
	if req.JitEnabled != nil || req.AllowLocal != nil {
		if err := h.store.SetIdPConnectionLoginToggles(ctx, conn.ID, req.JitEnabled, req.AllowLocal); err != nil {
			return nil, statusFromStoreErr(err)
		}
	}
	// Optional non-secret config overwrite; an empty map leaves config untouched.
	if cfg := req.GetConfig(); len(cfg) > 0 {
		if err := h.store.UpdateIdPConnectionConfig(ctx, conn.ID, stringMapToAny(cfg)); err != nil {
			return nil, statusFromStoreErr(err)
		}
	}
	// Re-hydrate so the response reflects the persisted toggles/config.
	conn, err = h.store.GetIdPConnection(ctx, conn.ID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.UpdateIdPConnectionResponse{Organization: orgToProto(conn, domain, d.Verified)}, nil
}

// ChangeOrgProtocol switches an existing org's IdP protocol (SAML<->OIDC) and
// RESETS the connection to the start, per. It reuses the same
// provisioner seam AddOrganization/DeleteOrganization use: it tears the old
// backend IdP down and re-provisions a fresh one (DISABLED) for the new
// protocol with the supplied config/secret_ref, then clears BOTH activation
// gates (verified + test_passed) and disables the connection — so the admin
// must re-verify the domain and re-run the IdP test before re-activating.
//
// Gates are reset in the DB FIRST, before touching the backend, so a failure
// mid-re-provision can never leave the org enabled and routing to a
// half-provisioned IdP: at worst it lands disabled + unverified (the "start"
// state), which is exactly the intended destination.
func (h *SSOAdminHandler) ChangeOrgProtocol(ctx context.Context, req *identityv1.ChangeOrgProtocolRequest) (*identityv1.ChangeOrgProtocolResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	protocol := strings.ToLower(strings.TrimSpace(req.GetProtocol()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	if protocol != "oidc" && protocol != "saml" {
		return nil, status.Error(codes.InvalidArgument, "protocol must be oidc or saml")
	}
	d, err := h.store.GetSSODomain(ctx, domain)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if d.ConnectionID == nil {
		return nil, status.Error(codes.FailedPrecondition, "domain has no sso connection registered")
	}
	conn, err := h.store.GetIdPConnection(ctx, *d.ConnectionID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if protocol == conn.Protocol {
		return nil, status.Errorf(codes.FailedPrecondition, "protocol is already %q", protocol)
	}

	// 1. Reset the org to the start FIRST: disable the connection and clear both
	// gates. Done before any backend mutation so the org is never left enabled
	// while its backend IdP is being torn down/rebuilt.
	if err := h.store.SetIdPConnectionEnabled(ctx, conn.ID, false); err != nil {
		return nil, statusFromStoreErr(err)
	}
	if err := h.store.ClearIdPTestPassed(ctx, conn.ID); err != nil {
		return nil, statusFromStoreErr(err)
	}
	if err := h.store.SetDomainVerified(ctx, domain, false); err != nil {
		return nil, statusFromStoreErr(err)
	}

	// 2. Tear the OLD backend connection down (best-effort, addressed exactly
	// like DeleteOrganization) before the new one is created under the same
	// tenant.
	if delErr := h.prov.DeleteConnection(ctx, polis.ConnectionRef{
		Domain:       domain,
		ClientID:     configString(conn.Config, polis.ConfigKeyPolisClientID),
		ClientSecret: h.resolvePolisSecret(ctx, conn),
		Tenant:       configString(conn.Config, polis.ConfigKeyPolisTenant),
		Product:      configString(conn.Config, polis.ConfigKeyPolisProduct),
	}); delErr != nil {
		lg := log.Ctx(ctx)
		lg.Warn().Err(delErr).Str("domain", domain).Str("connection_alias", conn.ConnectionAlias).
			Msg("sso: change-protocol best-effort teardown of prior backend connection failed")
	}

	// 3. Provision a fresh backend IdP (DISABLED) for the new protocol. On error
	// the org is already safely reset (step 1) — return the stable coded error;
	// the admin retries after fixing the backend.
	reqCfg := req.GetConfig()
	result, provErr := h.prov.CreateConnection(ctx, polis.ConnectionSpec{
		Alias:       conn.ConnectionAlias,
		DisplayName: conn.DisplayName,
		Protocol:    protocol,
		Domain:      domain,
		SecretRef:   req.GetSecretRef(),
		Config:      reqCfg,
	})
	if provErr != nil {
		dbg := log.Ctx(ctx)
		dbg.Debug().Err(provErr).Str("connection_alias", conn.ConnectionAlias).Str("domain", domain).Str("protocol", protocol).
			Msg("sso: change-protocol backend provisioning failed")
		return nil, errcodes.Error(ctx, errcodes.SSOProviderUnreachable(conn.OrgName, provErr))
	}

	// 4. Persist the new protocol + config + secret_ref, merging any
	// backend-issued teardown identifiers (Polis) so a later delete can
	// still address the connection.
	merged := stringMapToAny(reqCfg)
	if extra := result.ConfigKeys(); len(extra) > 0 {
		if merged == nil {
			merged = map[string]any{}
		}
		maps.Copy(merged, extra)
	}
	//: store the freshly issued client secret out-of-band and carry
	// only its reference on config. The ref is keyed by connection id, so a
	// re-provision overwrites the previous slot rather than orphaning it.
	if ref := h.persistPolisSecret(ctx, conn.ID.String(), result.ClientSecret); ref != "" {
		if merged == nil {
			merged = map[string]any{}
		}
		merged[polis.ConfigKeyPolisClientSecretRef] = ref
	}
	if err := h.store.UpdateIdPConnectionProtocol(ctx, conn.ID, protocol, merged, req.GetSecretRef()); err != nil {
		return nil, statusFromStoreErr(err)
	}

	// The org lost its verified proof (protocol reset) — surface it like a
	// rotation/recheck revoke so downstream notifiers know re-verification is due.
	h.emitSSODomainVerification(ctx, eventSSODomainVerificationRevoked, domain)

	conn, err = h.store.GetIdPConnection(ctx, conn.ID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.ChangeOrgProtocolResponse{Organization: orgToProto(conn, domain, false)}, nil
}

// StartDomainVerification arms DNS-TXT proof-of-ownership for a domain and
// returns the record to publish. The domain must already be registered (via
// AddOrganization). The token is STABLE: re-calling for a domain that already
// has a pending verification returns the SAME token, so a TXT record the admin
// already published stays valid — restarting never silently invalidates it. A
// new token is minted only on the first start, or when the caller sets
// rotate=true (the ONE explicit action that changes the value). Rotating also
// drops the domain back to unverified (SetDomainVerified false), since the
// prior proof no longer matches the new token.
func (h *SSOAdminHandler) StartDomainVerification(ctx context.Context, req *identityv1.StartDomainVerificationRequest) (*identityv1.StartDomainVerificationResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	if _, err := h.store.GetSSODomain(ctx, domain); err != nil {
		return nil, statusFromStoreErr(err)
	}

	// Reuse the existing pending token if verification was already started —
	// rotating it silently would invalidate a record the admin already
	// published. rotate=true is the explicit opt-in to mint a fresh token: it
	// skips the reuse branch and additionally revokes the prior verified proof,
	// since the old published record no longer matches the new token.
	rotate := req.GetRotate()
	var token string
	existing, gerr := h.store.GetDomainVerification(ctx, domain)
	if !rotate && gerr == nil && existing.Token != "" {
		token = existing.Token
	} else {
		t, terr := randomVerificationToken()
		if terr != nil {
			return nil, status.Errorf(codes.Internal, "generate verification token: %v", terr)
		}
		token = t
		if err := h.store.CreateDomainVerification(ctx, domain, token, "dns-txt"); err != nil {
			return nil, statusFromStoreErr(err)
		}
		if rotate {
			// Drop the ownership proof so a rotated domain is no longer treated as
			// verified until the fresh record is published + re-verified. The domain
			// row is known to exist (GetSSODomain above), so this only revokes; a
			// failure is logged, not fatal.
			if err := h.store.SetDomainVerified(ctx, domain, false); err != nil {
				lg := log.Ctx(ctx)
				lg.Warn().Err(err).Str("domain", domain).
					Msg("sso: token rotation failed to revoke prior verified proof")
			}
			h.emitSSODomainVerification(ctx, eventSSODomainVerificationRevoked, domain)
		}
	}

	recordName := verifyTXTRecordName(h.verifyTXTPrefix, domain)
	recordValue := verifyTXTRecordValue(h.verifyTXTPrefix, token)
	instructions := fmt.Sprintf(
		"Add a DNS TXT record named %q with the value %q, then call VerifyDomain to complete activation.",
		recordName, recordValue)

	h.emitSSODomainVerification(ctx, eventSSODomainVerificationRequested, domain)

	return &identityv1.StartDomainVerificationResponse{
		Token:          token,
		DnsRecordName:  recordName,
		DnsRecordValue: recordValue,
		Instructions:   instructions,
	}, nil
}

// VerifyDomain looks up the domain's DNS TXT records and checks whether any
// of them match the token minted by StartDomainVerification. A match flips
// the sso_domains verified gate (one of the two hard activation gates) and
// publishes sso.domain_verified. Neither a non-matching record nor a lookup
// failure (NXDOMAIN, resolver timeout, DNS propagation delay) is a gRPC
// error — both are ordinary, retryable "not yet verified" outcomes for an
// admin polling this RPC; a lookup failure is logged so operators can spot a
// persistently broken resolver, but the caller only ever sees verified=false.
func (h *SSOAdminHandler) VerifyDomain(ctx context.Context, req *identityv1.VerifyDomainRequest) (*identityv1.VerifyDomainResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	v, err := h.store.GetDomainVerification(ctx, domain)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	recordName := verifyTXTRecordName(h.verifyTXTPrefix, domain)
	records, err := h.txtLookup(ctx, recordName)
	if err != nil {
		lg := log.Ctx(ctx)
		lg.Warn().Err(err).Str("domain", domain).Str("record", recordName).
			Msg("sso: domain verification TXT lookup failed; reporting unverified")
		return &identityv1.VerifyDomainResponse{Verified: false}, nil
	}

	want := verifyTXTRecordValue(h.verifyTXTPrefix, v.Token)
	matched := slices.Contains(records, want)
	if !matched {
		return &identityv1.VerifyDomainResponse{Verified: false}, nil
	}

	if err := h.store.MarkDomainVerified(ctx, domain, time.Now()); err != nil {
		return nil, statusFromStoreErr(err)
	}
	h.emitSSODomainVerification(ctx, eventSSODomainVerified, domain)

	return &identityv1.VerifyDomainResponse{Verified: true}, nil
}

// emitSSODomainVerification publishes one domain-verification lifecycle event
// (eventSSODomainVerificationRequested / eventSSODomainVerified /
// eventSSODomainVerificationRevoked — all carry just the domain). Best-effort
// via emitSSOEvent.
func (h *SSOAdminHandler) emitSSODomainVerification(ctx context.Context, event, domain string) {
	emitSSOEvent(ctx, h.events, event, map[string]any{"domain": domain})
}

// RecheckVerifiedDomains re-validates that every VERIFIED sso domain's DNS-TXT
// proof still resolves; a domain whose record has disappeared is flipped back
// to unverified (drift → DiscoverMethod stops routing it to sso until it is
// re-proven). Best-effort per domain — a transient lookup error is skipped
// (never revokes on a lookup failure, only on a definitive no-match). Meant to
// run on a periodic ticker (see cmd/server/main.go). Returns how many verified
// domains were checked and how many were revoked. It is NOT AdminAuth-gated:
// it is invoked by the in-process ticker, never off an inbound RPC.
func (h *SSOAdminHandler) RecheckVerifiedDomains(ctx context.Context) (checked, revoked int, err error) {
	domains, err := h.store.ListSSODomains(ctx)
	if err != nil {
		return 0, 0, err
	}
	lg := log.Ctx(ctx)
	for _, d := range domains {
		if d.Method != "sso" || !d.Verified {
			continue
		}
		checked++
		v, gerr := h.store.GetDomainVerification(ctx, d.Domain)
		if gerr != nil || v.Token == "" {
			continue // no proof record to check against
		}
		records, lerr := h.txtLookup(ctx, verifyTXTRecordName(h.verifyTXTPrefix, d.Domain))
		if lerr != nil {
			continue // transient DNS failure — do NOT revoke on an error
		}
		want := verifyTXTRecordValue(h.verifyTXTPrefix, v.Token)
		matched := slices.Contains(records, want)
		if matched {
			continue
		}
		if serr := h.store.SetDomainVerified(ctx, d.Domain, false); serr != nil {
			lg.Error().Err(serr).Str("domain", d.Domain).Msg("sso: recheck failed to revoke drifted domain")
			continue
		}
		revoked++
		h.emitSSODomainVerification(ctx, eventSSODomainVerificationRevoked, d.Domain)
		lg.Warn().Str("domain", d.Domain).Msg("sso: domain verification revoked — TXT record no longer resolves")
	}
	return checked, revoked, nil
}

// eventSSOIdPTestFailed / eventSSOOrgActivated / eventSSOOrgDisabled are the
// lifecycle event names for the two-gate activation lifecycle: a
// failed admin test-login, and the org's enable/disable transitions. The
// welcome/notification email templates that consume these are a later task
// — this task only emits the events.
const (
	eventSSOIdPTestFailed = "sso.idp_test_failed"
	eventSSOOrgActivated  = "sso.activated"
	eventSSOOrgDisabled   = "sso.disabled"
)

// RecordIdPTestResult records the outcome of an admin-initiated IdP test
// login (the SSO admin page's "Test Connection" action, and the gateway's
// IdPTestRecorder seam). A successful test flips the connection's
// test_passed_at gate — one of the two hard gates ActivateOrganization
// enforces. A failed test is an ordinary, retryable recorded outcome (an
// admin fixing a misconfigured IdP and retrying) — it publishes
// sso.idp_test_failed but is never itself a gRPC error.
func (h *SSOAdminHandler) RecordIdPTestResult(ctx context.Context, req *identityv1.RecordIdPTestResultRequest) (*identityv1.RecordIdPTestResultResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	connID, err := uuid.Parse(req.GetConnectionId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "connection_id must be a valid uuid")
	}

	if req.GetSuccess() {
		if err := h.store.MarkIdPTestPassed(ctx, connID, time.Now()); err != nil {
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.RecordIdPTestResultResponse{}, nil
	}

	h.emitIdPTestFailed(ctx, connID, req.GetDetail())
	return &identityv1.RecordIdPTestResultResponse{}, nil
}

// emitIdPTestFailed publishes one sso.idp_test_failed lifecycle event carrying
// the connection id + failure detail. Best-effort via emitSSOEvent.
func (h *SSOAdminHandler) emitIdPTestFailed(ctx context.Context, connID uuid.UUID, detail string) {
	emitSSOEvent(ctx, h.events, eventSSOIdPTestFailed, map[string]any{
		"connectionId": connID.String(),
		"detail":       detail,
	})
}

// ActivateOrganization enables an organization's SSO connection for login.
// BOTH hard gates must already be satisfied — the domain's ownership proof
// (VerifyDomain) and a passed admin test login (RecordIdPTestResult) — since
// DiscoverMethod requires both before it will ever route to this
// connection; enabling with one gate short would only produce a false sense
// of activation, so this RPC rejects it outright with FailedPrecondition
// naming the unmet gate(s).
func (h *SSOAdminHandler) ActivateOrganization(ctx context.Context, req *identityv1.ActivateOrganizationRequest) (*identityv1.ActivateOrganizationResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	d, err := h.store.GetSSODomain(ctx, domain)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if d.ConnectionID == nil {
		return nil, status.Error(codes.FailedPrecondition, "domain has no sso connection registered")
	}
	conn, err := h.store.GetIdPConnection(ctx, *d.ConnectionID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	testPassed := conn.TestPassedAt != nil
	switch {
	case !d.Verified && !testPassed:
		return nil, status.Error(codes.FailedPrecondition, "activation requires both gates: domain is not verified and the IdP test has not passed")
	case !d.Verified:
		return nil, status.Error(codes.FailedPrecondition, "activation requires domain verification (VerifyDomain has not passed)")
	case !testPassed:
		return nil, status.Error(codes.FailedPrecondition, "activation requires a passed IdP test login (RecordIdPTestResult has not passed)")
	}

	if err := h.store.SetIdPConnectionEnabled(ctx, conn.ID, true); err != nil {
		return nil, statusFromStoreErr(err)
	}
	conn.Enabled = true
	h.emitOrgLifecycle(ctx, eventSSOOrgActivated, domain)

	return &identityv1.ActivateOrganizationResponse{Organization: orgToProto(conn, domain, d.Verified)}, nil
}

// DisableOrganization disables an organization's SSO connection, immediately
// removing it from DiscoverMethod's routing regardless of the verified/
// test-passed gates — disabling never re-checks them, it only ever narrows
// access.
func (h *SSOAdminHandler) DisableOrganization(ctx context.Context, req *identityv1.DisableOrganizationRequest) (*identityv1.DisableOrganizationResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	d, err := h.store.GetSSODomain(ctx, domain)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if d.ConnectionID == nil {
		return nil, status.Error(codes.FailedPrecondition, "domain has no sso connection registered")
	}
	conn, err := h.store.GetIdPConnection(ctx, *d.ConnectionID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if err := h.store.SetIdPConnectionEnabled(ctx, conn.ID, false); err != nil {
		return nil, statusFromStoreErr(err)
	}
	conn.Enabled = false
	h.emitOrgLifecycle(ctx, eventSSOOrgDisabled, domain)

	return &identityv1.DisableOrganizationResponse{Organization: orgToProto(conn, domain, d.Verified)}, nil
}

// emitOrgLifecycle publishes one org enable/disable lifecycle event (either
// eventSSOOrgActivated or eventSSOOrgDisabled — both carry just the domain).
// Best-effort via emitSSOEvent.
func (h *SSOAdminHandler) emitOrgLifecycle(ctx context.Context, event, domain string) {
	emitSSOEvent(ctx, h.events, event, map[string]any{"domain": domain})
}

// DeleteOrganization removes an organization's SSO registration entirely.
// The sso_domains routing row is deleted FIRST — before the idp_connections
// row — so a failure partway through can never leave a domain routing to a
// connection that no longer exists; the reverse order could. Deleting the
// idp_connections row (and best-effort the backend connection it backs)
// after that point is cleanup, not a routing hazard, so failures there
// are logged rather than failing the RPC — the organization is already gone
// from DiscoverMethod's perspective.
func (h *SSOAdminHandler) DeleteOrganization(ctx context.Context, req *identityv1.DeleteOrganizationRequest) (*identityv1.DeleteOrganizationResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	domain := strings.ToLower(strings.TrimSpace(req.GetDomain()))
	if domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain required")
	}
	d, err := h.store.GetSSODomain(ctx, domain)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	// Guard: refuse to delete a LIVE (enabled) organization — it must be disabled
	// first, so an in-use SSO connection is never torn out from under active
	// sessions. A disabled / never-activated org may be deleted directly.
	if d.ConnectionID != nil {
		if conn, cerr := h.store.GetIdPConnection(ctx, *d.ConnectionID); cerr == nil && conn.Enabled {
			return nil, status.Error(codes.FailedPrecondition, "disable the organization before deleting it")
		}
	}

	if err := h.store.DeleteSSODomain(ctx, domain); err != nil {
		return nil, statusFromStoreErr(err)
	}

	if d.ConnectionID != nil {
		lg := log.Ctx(ctx)
		conn, cerr := h.store.GetIdPConnection(ctx, *d.ConnectionID)
		if cerr != nil {
			lg.Warn().Err(cerr).Str("domain", domain).Str("connection_id", d.ConnectionID.String()).
				Msg("sso: delete organization could not resolve connection for cleanup; domain routing already removed")
		} else {
			if delErr := h.store.DeleteIdPConnection(ctx, conn.ID); delErr != nil {
				lg.Error().Err(delErr).Str("domain", domain).Str("connection_id", conn.ID.String()).
					Msg("sso: delete organization failed to remove idp connection row; domain routing already removed")
			}
			// Best-effort backend teardown through the same provisioner seam
			// AddOrganization created the connection with, addressed by the
			// clientID and tenant/product persisted on config.
			if provErr := h.prov.DeleteConnection(ctx, polis.ConnectionRef{
				Domain:       domain,
				ClientID:     configString(conn.Config, polis.ConfigKeyPolisClientID),
				ClientSecret: h.resolvePolisSecret(ctx, conn),
				Tenant:       configString(conn.Config, polis.ConfigKeyPolisTenant),
				Product:      configString(conn.Config, polis.ConfigKeyPolisProduct),
			}); provErr != nil {
				lg.Warn().Err(provErr).Str("domain", domain).Str("connection_alias", conn.ConnectionAlias).
					Msg("sso: delete organization best-effort backend connection delete failed")
			}
		}
	}

	return &identityv1.DeleteOrganizationResponse{Domain: domain}, nil
}

// eventSSOSPCertRotated is the lifecycle event name emitted when
// ForceRotateSPCertificate cuts over to a freshly-minted SP signing
// certificate.
const eventSSOSPCertRotated = "sso.sp_cert_rotated"

// GetSPCertificate returns the platform's active SAML SP signing certificate
// — PUBLIC material only. The wire response has no private-key field at all
// (compile-time guarantee), and this method never reads spCertService's key
// store, only the store's public cert row and the rendered SP metadata.
func (h *SSOAdminHandler) GetSPCertificate(ctx context.Context, _ *identityv1.GetSPCertificateRequest) (*identityv1.GetSPCertificateResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	if err := h.requireSPCert(); err != nil {
		return nil, err
	}
	c, err := h.store.GetActiveSPCertificate(ctx)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	metadataXML, err := h.sp.SPMetadataXML(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "render sp metadata: %v", err)
	}
	return &identityv1.GetSPCertificateResponse{Certificate: spCertToProto(c, metadataXML)}, nil
}

// ListSPCertificates enumerates every SP signing certificate row (active,
// overlapping, and past-overlap) — PUBLIC material only, no key. Per-row
// sp_metadata_xml is left empty: SP metadata is a single shared document
// (rendered by GetSPCertificate), not a per-certificate one.
func (h *SSOAdminHandler) ListSPCertificates(ctx context.Context, _ *identityv1.ListSPCertificatesRequest) (*identityv1.ListSPCertificatesResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	if err := h.requireSPCert(); err != nil {
		return nil, err
	}
	rows, err := h.store.ListSPCertificates(ctx)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.SPCertificate, 0, len(rows))
	for _, c := range rows {
		out = append(out, spCertToProto(c, ""))
	}
	return &identityv1.ListSPCertificatesResponse{Certificates: out}, nil
}

// ForceRotateSPCertificate mints a fresh SP signing certificate, activates it
// (retaining the prior cert through its graceful overlap window), and
// publishes sso.sp_cert_rotated. The private key of the new cert lands only
// in spCertService's key store — this RPC returns public material only.
func (h *SSOAdminHandler) ForceRotateSPCertificate(ctx context.Context, _ *identityv1.ForceRotateSPCertificateRequest) (*identityv1.ForceRotateSPCertificateResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	if err := h.requireSPCert(); err != nil {
		return nil, err
	}
	c, err := h.sp.ForceRotate(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "force rotate sp certificate: %v", err)
	}
	metadataXML, err := h.sp.SPMetadataXML(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "render sp metadata: %v", err)
	}
	h.emitSPCertRotated(ctx, c.Serial)
	return &identityv1.ForceRotateSPCertificateResponse{Certificate: spCertToProto(c, metadataXML)}, nil
}

// emitSPCertRotated publishes one sso.sp_cert_rotated lifecycle event carrying
// the new certificate serial. Best-effort via emitSSOEvent.
func (h *SSOAdminHandler) emitSPCertRotated(ctx context.Context, serial string) {
	emitSSOEvent(ctx, h.events, eventSSOSPCertRotated, map[string]any{"serial": serial})
}

// auditEventBreakGlassLogin is the audit_buffer event_type for a durable
// break-glass login record.
const auditEventBreakGlassLogin = "security.break_glass.login"

// RecordBreakGlassLogin durably records a successful break-glass local login.
// It is the identity-side home of the security trail the gateway used to keep
// only as a best-effort local seam : it (a) writes
// an audit row to the outbox so the login is durably recorded even if the
// broker is down, and (b) publishes user.break_glass.login for the site-admin
// notifier fan-out.
//
// Intentionally NOT gated by AdminAuth: it is invoked mid-login, before the
// break-glass caller has a session or forwarded admin claims (mirroring the
// unauthenticated CheckBreakGlassEligibility on the read service). Mesh-level
// mTLS restricts who can reach identity. Because the RPC is ungated, it
// re-runs the SAME eligibility rule as CheckBreakGlassEligibility on the
// supplied email and REJECTS an ineligible one with PermissionDenied — so an
// in-mesh caller cannot forge a durable break-glass audit row / site-admin
// alert for an arbitrary address. Only a genuinely break-glass-eligible
// identity can produce a record. The durable audit write is attempted after
// the gate and any failure is returned so the gateway can alert; the event
// emit is best-effort.
func (h *SSOAdminHandler) RecordBreakGlassLogin(ctx context.Context, req *identityv1.RecordBreakGlassLoginRequest) (*identityv1.RecordBreakGlassLoginResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	reason := strings.TrimSpace(req.GetReason())

	// Eligibility gate: only an identity that actually qualifies for break-glass
	// (privileged AND holding a local credential) may produce a break-glass
	// record. A lookup error is Internal; an ineligible/unknown email is
	// PermissionDenied naming the machine reason.
	eligible, eligReason, err := h.store.BreakGlassLoginEligible(ctx, email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "break-glass eligibility: %v", err)
	}
	if !eligible {
		lg := log.Ctx(ctx)
		lg.Warn().Str("email", email).Str("reason", eligReason).
			Msg("break-glass: refusing to record — email not break-glass-eligible")
		return nil, status.Errorf(codes.PermissionDenied, "email not break-glass-eligible: %s", eligReason)
	}

	// Resolve the optional actor uuid; a malformed value is non-fatal — the row
	// still records the email + reason without an actor link.
	var actorUserID *uuid.UUID
	if raw := strings.TrimSpace(req.GetActorUserId()); raw != "" {
		if id, perr := uuid.Parse(raw); perr == nil {
			actorUserID = &id
		} else {
			lg := log.Ctx(ctx)
			lg.Warn().Str("actor_user_id", raw).
				Msg("break-glass: unparseable actor_user_id, recording without actor link")
		}
	}

	payload := map[string]any{"email": email}
	if reason != "" {
		payload["reason"] = reason
	}

	// Durable first: the outbox row is the record of truth. A failure here is
	// returned so the gateway can surface/alert — but the gateway must still
	// never block the login on it.
	if err := h.store.EmitAudit(ctx, store.AuditEvent{
		EventType:   auditEventBreakGlassLogin,
		ActorUserID: actorUserID,
		Payload:     payload,
	}); err != nil {
		lg := log.Ctx(ctx)
		lg.Error().Err(err).Str("email", email).
			Msg("break-glass: durable audit write failed")
		return nil, status.Errorf(codes.Internal, "record break-glass audit: %v", err)
	}

	// Best-effort fan-out event (swallowed on failure — the durable row above
	// is the authoritative record).
	vars := map[string]any{"email": email}
	if reason != "" {
		vars["reason"] = reason
	}
	emitSSOEvent(ctx, h.events, eventUserBreakGlassLogin, vars)

	return &identityv1.RecordBreakGlassLoginResponse{}, nil
}

// AddGroupMapping registers a single IdP-claim-value -> platform-group
// mapping for a connection, consumed by ApplyIdPGroupMappings during JIT
// group sync on a subsequent SSO login. The target is a group id (not a
// name) — see store.IdPGroupMapping.
func (h *SSOAdminHandler) AddGroupMapping(ctx context.Context, req *identityv1.AddGroupMappingRequest) (*identityv1.AddGroupMappingResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	connID, err := parseUUID(req.GetConnectionId(), "connection_id")
	if err != nil {
		return nil, err
	}
	targetGroupID, err := parseUUID(req.GetTargetGroupId(), "target_group_id")
	if err != nil {
		return nil, err
	}
	idpValue := strings.TrimSpace(req.GetIdpGroupClaimValue())
	if idpValue == "" {
		return nil, status.Error(codes.InvalidArgument, "idp_group_claim_value required")
	}

	m, err := h.store.AddIdPGroupMapping(ctx, connID, idpValue, targetGroupID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.AddGroupMappingResponse{Mapping: groupMappingToProto(m)}, nil
}

// ListGroupMappings enumerates every group mapping configured for a
// connection.
func (h *SSOAdminHandler) ListGroupMappings(ctx context.Context, req *identityv1.ListGroupMappingsRequest) (*identityv1.ListGroupMappingsResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	connID, err := parseUUID(req.GetConnectionId(), "connection_id")
	if err != nil {
		return nil, err
	}

	rows, err := h.store.ListIdPGroupMappings(ctx, connID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.GroupMapping, 0, len(rows))
	for _, m := range rows {
		out = append(out, groupMappingToProto(m))
	}
	return &identityv1.ListGroupMappingsResponse{Mappings: out}, nil
}

// DeleteGroupMapping removes a single group mapping by id.
func (h *SSOAdminHandler) DeleteGroupMapping(ctx context.Context, req *identityv1.DeleteGroupMappingRequest) (*identityv1.DeleteGroupMappingResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetMappingId(), "mapping_id")
	if err != nil {
		return nil, err
	}

	if err := h.store.DeleteIdPGroupMapping(ctx, id); err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.DeleteGroupMappingResponse{MappingId: req.GetMappingId()}, nil
}

// groupMappingToProto renders a store.IdPGroupMapping as the wire
// GroupMapping message.
func groupMappingToProto(m store.IdPGroupMapping) *identityv1.GroupMapping {
	return &identityv1.GroupMapping{
		Id:                 m.ID.String(),
		ConnectionId:       m.ConnectionID.String(),
		IdpGroupClaimValue: m.IdPGroupClaimValue,
		TargetGroupId:      m.TargetGroupID.String(),
	}
}

// spCertToProto renders a store.SPCertificate as the wire SPCertificate
// — PUBLIC fields only (serial, cert PEM, not_after, active). The caller
// supplies metadataXML (empty for list rows, the rendered SP metadata for
// Get/ForceRotate) since metadata is shared across every serving cert, not
// per-row data. There is no field, and never will be, for the private key.
func spCertToProto(c store.SPCertificate, metadataXML string) *identityv1.SPCertificate {
	return &identityv1.SPCertificate{
		Serial:        c.Serial,
		CertPem:       c.CertPEM,
		SpMetadataXml: metadataXML,
		NotAfter:      c.NotAfter.UTC().Format(time.RFC3339),
		Active:        c.Active,
	}
}

// randomVerificationToken mints a 24-random-byte, base64url (no padding)
// domain-ownership proof token.
func randomVerificationToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// verifyTXTRecordName renders the DNS-TXT record name a domain's
// verification is checked under: "_<prefix>.<domain>".
func verifyTXTRecordName(prefix, domain string) string {
	return "_" + prefix + "." + domain
}

// verifyTXTRecordValue renders the expected DNS-TXT record value for a given
// token: "<prefix>=<token>".
func verifyTXTRecordValue(prefix, token string) string {
	return prefix + "=" + token
}

// actorLabel renders an audit label for the SSO domain's created_by column:
// the platform user id on the gateway path, else the operator label on the
// admin CLI path (may be empty — created_by defaults to ”).
func actorLabel(a adminActor) string {
	if a.ActorUserID != "" {
		return a.ActorUserID
	}
	return a.ActorExternal
}

// connectionAlias derives a stable, DNS-ish slug for the connection routing alias
// (the connection_alias column) from the org name, falling back to the domain.
// DiscoverMethod returns it, so it must be deterministic for a given org/domain.
func connectionAlias(orgName, domain string) string {
	if s := slugify(orgName); s != "" {
		return s
	}
	return slugify(domain)
}

// slugify lower-cases s and collapses any run of non-alphanumeric characters
// into a single '-', trimming leading/trailing '-'.
func slugify(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// stringMapToAny widens a proto string map into the map[string]any the store
// persists as JSONB.
func stringMapToAny(in map[string]string) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// configString reads a string value from a connection's config JSONB map,
// returning "" when the key is absent or not a string. Used to recover the
// backend teardown identifiers (polis*) persisted on the connection.
func configString(cfg map[string]any, key string) string {
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

// orgToProto renders a store.IdPConnection (+ its domain and the domain's
// verified gate) as the wire Organization. test_passed is derived from the
// connection's gating state; verified is passed in by the caller since it
// lives on the sso_domains row, not the connection.
func orgToProto(c store.IdPConnection, domain string, verified bool) *identityv1.Organization {
	return &identityv1.Organization{
		Domain:          domain,
		OrgName:         c.OrgName,
		Protocol:        c.Protocol,
		DisplayName:     c.DisplayName,
		ConnectionAlias: c.ConnectionAlias,
		Verified:        verified,
		TestPassed:      c.TestPassedAt != nil,
		Enabled:         c.Enabled,
		ConnectionId:    c.ID.String(),
		JitEnabled:      c.JitEnabled,
		AllowLocal:      c.AllowLocal,
	}
}
