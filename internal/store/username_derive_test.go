// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import "testing"

// TestDeriveUsernameBase is a pure (Docker-free) unit test of the SSO/JIT
// username derivation: lowercased email local-part.
func TestDeriveUsernameBase(t *testing.T) {
	cases := map[string]string{
		"alice@example.org":       "alice",
		"Alice.Smith@Example.ORG": "alice.smith",
		"  bob@x.example.org  ":   "bob", // trimmed then local-part
		"nolocalpart@":            "nolocalpart",
		"noatsign":                "noatsign",
		"":                        "",
	}
	for in, want := range cases {
		if got := deriveUsernameBase(in); got != want {
			t.Errorf("deriveUsernameBase(%q) = %q, want %q", in, got, want)
		}
	}
}
