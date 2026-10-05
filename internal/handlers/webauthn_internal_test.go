// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import "testing"

// Direct unit coverage of the clone-detection predicate (WebAuthn §6.1.1):
// whenever either counter is non-zero, an assertion's counter must STRICTLY
// exceed the stored one; a pair of zeros means the authenticator does not
// implement a counter and is allowed.
func TestSignCountRegressed(t *testing.T) {
	cases := []struct {
		name           string
		stored, latest uint32
		want           bool
	}{
		{"no counter support (0,0) allowed", 0, 0, false},
		{"first real use advances (0→1)", 0, 1, false},
		{"normal advance (5→6)", 5, 6, false},
		{"big jump allowed (5→500)", 5, 500, false},
		{"equal counter rejected (5→5)", 5, 5, true},
		{"regression rejected (5→3)", 5, 3, true},
		{"drop to zero rejected (1→0)", 1, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := signCountRegressed(tc.stored, tc.latest); got != tc.want {
				t.Fatalf("signCountRegressed(%d, %d) = %v, want %v", tc.stored, tc.latest, got, tc.want)
			}
		})
	}
}
