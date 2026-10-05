// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package polis

import (
	"encoding/xml"
	"strings"
	"testing"
)

// TestSynthesizeSAMLIdPMetadata_WellFormed verifies the synthesized document is
// well-formed XML and carries the entityID, normalized certificate body, and
// SSO URL from the three wizard fields — the load-bearing contract Polis's
// rawMetadata parse depends on.
func TestSynthesizeSAMLIdPMetadata_WellFormed(t *testing.T) {
	const (
		entityID = "https://idp.example.net/saml2?idpid=C01abc23"
		ssoURL   = "https://idp.example.net/saml2/sso?idpid=C01abc23"
	)
	// A PEM-armored cert with newlines; synthesis must strip armor + whitespace
	// down to the bare base64 body.
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIDdummyBODY1\nMIIDdummyBODY2\n-----END CERTIFICATE-----\n"

	xmlOut, err := SynthesizeSAMLIdPMetadata(entityID, ssoURL, certPEM)
	if err != nil {
		t.Fatalf("SynthesizeSAMLIdPMetadata: %v", err)
	}

	// Well-formed: the stdlib decoder must consume the whole document.
	dec := xml.NewDecoder(strings.NewReader(xmlOut))
	for {
		_, terr := dec.Token()
		if terr != nil {
			if terr.Error() == "EOF" {
				break
			}
			t.Fatalf("synthesized metadata is not well-formed XML: %v\n%s", terr, xmlOut)
		}
	}

	if !strings.Contains(xmlOut, `entityID="`+entityID+`"`) {
		t.Errorf("metadata missing entityID; got:\n%s", xmlOut)
	}
	// Certificate body must be the bare base64 (armor + newlines removed).
	if !strings.Contains(xmlOut, "<ds:X509Certificate>MIIDdummyBODY1MIIDdummyBODY2</ds:X509Certificate>") {
		t.Errorf("metadata missing normalized cert body; got:\n%s", xmlOut)
	}
	if strings.Contains(xmlOut, "BEGIN CERTIFICATE") {
		t.Errorf("metadata leaked PEM armor; got:\n%s", xmlOut)
	}
	// Both SSO bindings advertised at the SSO URL.
	if strings.Count(xmlOut, `Location="`+ssoURL+`"`) != 2 {
		t.Errorf("expected both SSO bindings at the SSO URL; got:\n%s", xmlOut)
	}
	if !strings.Contains(xmlOut, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect") ||
		!strings.Contains(xmlOut, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST") {
		t.Errorf("expected both HTTP-Redirect and HTTP-POST bindings; got:\n%s", xmlOut)
	}
}

// TestSynthesizeSAMLIdPMetadata_EscapesSpecialChars ensures an entityID / SSO
// URL containing XML metacharacters is escaped rather than breaking out of the
// document (a well-formedness + injection guard).
func TestSynthesizeSAMLIdPMetadata_EscapesSpecialChars(t *testing.T) {
	xmlOut, err := SynthesizeSAMLIdPMetadata(`https://idp/?a=1&b=2<x>`, `https://idp/sso?q="v"`, "AAAAbase64")
	if err != nil {
		t.Fatalf("SynthesizeSAMLIdPMetadata: %v", err)
	}
	if strings.Contains(xmlOut, "&b=2<x>") {
		t.Errorf("entityID special chars not escaped; got:\n%s", xmlOut)
	}
	// Must still be well-formed after escaping.
	if err := xml.Unmarshal([]byte(strings.TrimPrefix(xmlOut, `<?xml version="1.0" encoding="UTF-8"?>`)), new(struct {
		XMLName xml.Name
	})); err != nil {
		t.Errorf("escaped metadata not well-formed: %v\n%s", err, xmlOut)
	}
}

// TestSynthesizeSAMLIdPMetadata_RequiresAllFields rejects a missing field
// rather than emitting a metadata document Polis would reject downstream.
func TestSynthesizeSAMLIdPMetadata_RequiresAllFields(t *testing.T) {
	cases := []struct {
		name                   string
		entityID, ssoURL, cert string
	}{
		{"missing entityID", "", "https://idp/sso", "AAAA"},
		{"missing ssoURL", "https://idp", "", "AAAA"},
		{"missing cert", "https://idp", "https://idp/sso", "   "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SynthesizeSAMLIdPMetadata(tc.entityID, tc.ssoURL, tc.cert); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}
