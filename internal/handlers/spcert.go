// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	certkit "github.com/Bugs5382/go-certkit"
	"github.com/Steward-GRC/steward-identity/internal/sso/spkeys"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// Platform SP identity defaults. The SP signing certificate is a platform
// singleton (not per-connection): its subject/SANs identify the Policy SP in
// SAML metadata. The entityID and CommonName are fixed for now;
// they are stable defaults so EnsureInitial can mint the first cert on boot.
const (
	defaultSPCommonName = "steward-identity-sp"
	defaultSPEntityID   = "urn:policy:identity:sp"
)

// spCertService owns the platform SAML SP signing certificate: it generates the
// first one on boot, force-rotates with a graceful overlap window, and renders
// SP metadata advertising every currently-serving public cert. The private key
// is written only to keys (a k8s Secret) — never to the DB and never returned.
type spCertService struct {
	keys    spkeys.Store
	store   *store.Store
	ttl     time.Duration
	overlap time.Duration
}

// NewSPCertService constructs the SP-certificate service. ttl is the generated
// certificate lifetime; overlap is how long a rotated-out cert keeps serving
// (advertised in metadata, key retained) before it is considered retired.
func NewSPCertService(keys spkeys.Store, st *store.Store, ttl, overlap time.Duration) *spCertService {
	return &spCertService{keys: keys, store: st, ttl: ttl, overlap: overlap}
}

// EnsureInitial mints the first SP certificate when none is active yet. It is
// idempotent: once an active cert exists it returns without regenerating, so it
// is safe to call unconditionally on every boot. The private key is written to
// the Secret BEFORE the public row is inserted, so a cert is never advertised
// without its key available.
func (s *spCertService) EnsureInitial(ctx context.Context) error {
	if _, err := s.store.GetActiveSPCertificate(ctx); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("spcert: check active: %w", err)
	}

	b, err := certkit.GenerateSelfSigned(certkit.GenOpts{
		CommonName: defaultSPCommonName,
		DNSNames:   []string{defaultSPCommonName},
		TTL:        s.ttl,
	})
	if err != nil {
		return fmt.Errorf("spcert: generate initial: %w", err)
	}
	return s.persistActive(ctx, b, true)
}

// ForceRotate generates a fresh keypair + self-signed cert, publishes it
// alongside the current one, and cuts the active pointer over to it. The prior
// active cert's row is retained (its retired_at set to now+overlap) so it keeps
// signing/validating through the overlap window; a sweeper reclaims rows once
// past overlap. The private key of the new cert lands only in the Secret.
// Returns the new active certificate row.
func (s *spCertService) ForceRotate(ctx context.Context) (store.SPCertificate, error) {
	// Require an existing active cert to rotate from; callers run EnsureInitial
	// on boot, so this is only hit if rotation is requested before bootstrap.
	if _, err := s.store.GetActiveSPCertificate(ctx); err != nil {
		return store.SPCertificate{}, fmt.Errorf("spcert: load current: %w", err)
	}

	// The platform SP subject/SANs are fixed defaults, so Rotate derives them
	// from this reconstructed Bundle; explicit opts carry the TTL (the store
	// row does not retain it).
	curBundle := certkit.Bundle{
		Meta: certkit.Meta{
			Subject: "CN=" + defaultSPCommonName,
			SANs:    []string{defaultSPCommonName},
		},
	}
	b, err := certkit.Rotate(curBundle, certkit.GenOpts{TTL: s.ttl})
	if err != nil {
		return store.SPCertificate{}, fmt.Errorf("spcert: rotate: %w", err)
	}

	if err := s.persistActive(ctx, b, false); err != nil {
		return store.SPCertificate{}, err
	}
	newID, err := s.serialToID(ctx, b.Meta.SerialNumber)
	if err != nil {
		return store.SPCertificate{}, err
	}
	if err := s.store.SetActiveSPCertificate(ctx, newID); err != nil {
		return store.SPCertificate{}, fmt.Errorf("spcert: set active: %w", err)
	}
	// Schedule every other (now-inactive) cert to retire after the overlap.
	if _, err := s.store.RetireOldSPCertificates(ctx, newID, time.Now().Add(s.overlap)); err != nil {
		return store.SPCertificate{}, fmt.Errorf("spcert: retire old: %w", err)
	}

	return s.store.GetActiveSPCertificate(ctx)
}

// SPMetadataXML renders SP SAML metadata embedding a signing KeyDescriptor for
// every currently-serving public cert: the active one plus any overlapping
// (retired_at in the future) predecessors. Past-overlap certs are excluded. The
// private key is never present in the output.
func (s *spCertService) SPMetadataXML(ctx context.Context) (string, error) {
	all, err := s.store.ListSPCertificates(ctx)
	if err != nil {
		return "", fmt.Errorf("spcert: list: %w", err)
	}
	now := time.Now()
	var kds []keyDescriptor
	for _, c := range all {
		if c.RetiredAt != nil && !c.RetiredAt.After(now) {
			continue // past-overlap: no longer advertised
		}
		b64, err := certPEMToB64DER(c.CertPEM)
		if err != nil {
			return "", fmt.Errorf("spcert: encode cert %s: %w", c.Serial, err)
		}
		kds = append(kds, keyDescriptor{
			Use:     "signing",
			KeyInfo: keyInfo{X509Data: x509Data{X509Certificate: b64}},
		})
	}

	ed := entityDescriptor{
		EntityID: defaultSPEntityID,
		SPSSO: spSSODescriptor{
			Protocol:       "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptors: kds,
		},
	}
	out, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return "", fmt.Errorf("spcert: marshal metadata: %w", err)
	}
	return xml.Header + string(out), nil
}

// persistActive writes the key to the Secret (keyed by serial), then inserts
// the public cert row. active controls the initial active flag on the row.
func (s *spCertService) persistActive(ctx context.Context, b certkit.Bundle, active bool) error {
	serial := b.Meta.SerialNumber
	// Key first: never advertise a cert whose key is not yet retrievable.
	if err := s.keys.PutKey(ctx, serial, b.KeyPEM); err != nil {
		return fmt.Errorf("spcert: put key: %w", err)
	}
	row := store.SPCertificate{
		ID:        uuid.New(),
		Serial:    serial,
		CertPEM:   string(b.LeafPEM),
		SecretRef: serial,
		Active:    active,
		NotAfter:  b.Meta.NotAfter,
	}
	if err := s.store.InsertSPCertificate(ctx, row); err != nil {
		return fmt.Errorf("spcert: insert cert: %w", err)
	}
	return nil
}

// serialToID resolves the row id for a serial by scanning the list. The set is
// tiny (active + a handful of overlapping certs), so a full list is cheaper
// than adding a bespoke lookup path.
func (s *spCertService) serialToID(ctx context.Context, serial string) (uuid.UUID, error) {
	all, err := s.store.ListSPCertificates(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("spcert: list for serial: %w", err)
	}
	for _, c := range all {
		if c.Serial == serial {
			return c.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("spcert: serial %s not found after insert", serial)
}

// certPEMToB64DER strips the PEM armor from a certificate and returns the raw
// DER as standard base64 — the form SAML metadata's <X509Certificate> expects.
func certPEMToB64DER(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", errors.New("no PEM block")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

// SAML metadata (subset) — urn:oasis:names:tc:SAML:2.0:metadata with a
// signing-only SPSSODescriptor. Enough to publish the SP's signing certs; the
// full descriptor (ACS/SLO endpoints) is layered on in a later task.
type entityDescriptor struct {
	XMLName  xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string          `xml:"entityID,attr"`
	SPSSO    spSSODescriptor `xml:"SPSSODescriptor"`
}

type spSSODescriptor struct {
	Protocol       string          `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptors []keyDescriptor `xml:"KeyDescriptor"`
}

type keyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo keyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type keyInfo struct {
	X509Data x509Data `xml:"X509Data"`
}

type x509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}
