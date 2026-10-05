// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package polis

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
)

// pemArmorRE matches the PEM armor lines (-----BEGIN X----- / -----END X-----)
// around a certificate body, regardless of the label, so a wizard-supplied PEM
// and a bare base64 body both reduce to the same X509Certificate content.
var pemArmorRE = regexp.MustCompile(`-----(BEGIN|END)[^-]*-----`)

// normalizeSigningCertificate reduces a caller-supplied IdP signing certificate
// to the BARE base64 DER body a SAML metadata <ds:X509Certificate> element
// carries: PEM armor removed, all whitespace removed. Idempotent — an
// already-bare base64 body passes through unchanged.
func normalizeSigningCertificate(cert string) string {
	if strings.TrimSpace(cert) == "" {
		return ""
	}
	stripped := pemArmorRE.ReplaceAllString(cert, "")
	return strings.Join(strings.FieldsFunc(stripped, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
	}), "")
}

// SynthesizeSAMLIdPMetadata builds a minimal, self-contained SAML 2.0 IdP
// EntityDescriptor from the three fields the onboarding wizard collects for a
// SAML organisation (entityID, single-sign-on redirect URL, and
// the IdP signing certificate) so Polis, which wants full IdP metadata XML,
// can be handed rawMetadata even though the wizard never produced a metadata
// document.
//
// The certificate is normalized to the bare base64 body a <ds:X509Certificate>
// element carries. entityID and ssoURL are XML-escaped. Both the HTTP-Redirect
// and HTTP-POST SingleSignOnService bindings are advertised at the same
// location so Polis can choose either. It is a pure function (no I/O) so it is
// trivially unit-testable.
func SynthesizeSAMLIdPMetadata(entityID, ssoURL, signingCert string) (string, error) {
	entityID = strings.TrimSpace(entityID)
	ssoURL = strings.TrimSpace(ssoURL)
	cert := normalizeSigningCertificate(signingCert)
	if entityID == "" {
		return "", fmt.Errorf("saml metadata: entityId is required")
	}
	if ssoURL == "" {
		return "", fmt.Errorf("saml metadata: singleSignOnServiceUrl is required")
	}
	if cert == "" {
		return "", fmt.Errorf("saml metadata: signingCertificate is required")
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="`)
	b.WriteString(xmlEscape(entityID))
	b.WriteString(`">`)
	b.WriteString(`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
	b.WriteString(`<KeyDescriptor use="signing">`)
	b.WriteString(`<ds:KeyInfo><ds:X509Data><ds:X509Certificate>`)
	b.WriteString(xmlEscape(cert))
	b.WriteString(`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`)
	b.WriteString(`</KeyDescriptor>`)
	b.WriteString(`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="`)
	b.WriteString(xmlEscape(ssoURL))
	b.WriteString(`"/>`)
	b.WriteString(`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="`)
	b.WriteString(xmlEscape(ssoURL))
	b.WriteString(`"/>`)
	b.WriteString(`</IDPSSODescriptor>`)
	b.WriteString(`</EntityDescriptor>`)
	return b.String(), nil
}

// xmlEscape escapes a value for safe inclusion in an XML attribute or text
// node, using the stdlib escaper so quotes, angle brackets, and ampersands in
// an entityID or SSO URL can never break out of the document.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return s
	}
	return buf.String()
}
