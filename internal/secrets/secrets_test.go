// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package secrets_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Steward-GRC/steward-identity/internal/secrets"
)

// testKeyHex is a 32-byte key in hex (64 chars) — the documented TOTP_ENC_KEY shape.
const testKeyHex = "6368616e676520746869732070617373776f726420746f206120736563726574"

func mustCipher(t *testing.T, keyStr string) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewFromString(keyStr)
	if err != nil {
		t.Fatalf("NewFromString(%q): %v", keyStr, err)
	}
	return c
}

func TestSealOpenRoundTrip(t *testing.T) {
	c := mustCipher(t, testKeyHex)
	for _, plain := range []string{"JBSWY3DPEHPK3PXP", "", "unicode é secret"} {
		sealed, err := c.Seal(plain)
		if err != nil {
			t.Fatalf("Seal(%q): %v", plain, err)
		}
		if strings.Contains(sealed, plain) && plain != "" {
			t.Fatalf("sealed output contains plaintext")
		}
		got, err := c.Open(sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if got != plain {
			t.Fatalf("round trip: got %q want %q", got, plain)
		}
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	c := mustCipher(t, testKeyHex)
	a, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if a == b {
		t.Fatal("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	c := mustCipher(t, testKeyHex)
	other := mustCipher(t, strings.Repeat("ab", 32))
	sealed, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("Open with the wrong key must fail")
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	c := mustCipher(t, testKeyHex)
	sealed, err := c.Seal("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("sealed value must be std base64: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	if _, err := c.Open(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("Open of tampered ciphertext must fail")
	}
	if _, err := c.Open("not base64 at all!!!"); err == nil {
		t.Fatal("Open of garbage must fail")
	}
}

func TestNewFromStringKeyShapes(t *testing.T) {
	// base64 of 32 bytes is accepted too.
	b64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if _, err := secrets.NewFromString(b64); err != nil {
		t.Fatalf("base64 32-byte key rejected: %v", err)
	}
	for _, bad := range []string{"", "deadbeef", strings.Repeat("zz", 32), base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		if _, err := secrets.NewFromString(bad); err == nil {
			t.Fatalf("NewFromString(%q) must reject non-32-byte keys", bad)
		}
	}
}
