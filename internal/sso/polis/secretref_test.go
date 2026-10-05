// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package polis_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/sso/polis"
)

// The config column is plain JSONB and lands in every backup, so the client
// secret must never be stored there; only a reference to it.
func TestConfigKeys_NeverCarriesPlaintextClientSecret(t *testing.T) {
	const secret = "CSEC-must-not-be-persisted"
	res := polis.ConnectionResult{
		ClientID:     "CID-abc",
		ClientSecret: secret,
		Tenant:       "partner.example.net",
		Product:      "steward",
	}

	keys := res.ConfigKeys()

	for k, v := range keys {
		require.NotEqual(t, secret, v, "key %q carries the plaintext client secret", k)
	}
	require.Equal(t, map[string]any{
		polis.ConfigKeyPolisClientID: "CID-abc",
		polis.ConfigKeyPolisTenant:   "partner.example.net",
		polis.ConfigKeyPolisProduct:  "steward",
	}, keys)
}

// TestSecretRefFor_IsStableAndNotTheSecret pins the reference scheme: the value
// stored in config is derived from the connection id, carries no secret
// material, and is stable so a rotation can overwrite the same slot.
func TestSecretRefFor_IsStableAndNotTheSecret(t *testing.T) {
	const connID = "5f79d38d-70f6-4b4c-8001-d8ae992fd375"

	ref := polis.PolisClientSecretRef(connID)

	require.NotEmpty(t, ref)
	require.Contains(t, ref, connID, "the ref must address the connection it belongs to")
	require.Equal(t, ref, polis.PolisClientSecretRef(connID), "ref must be stable for rotation")
	require.NotEqual(t, ref, polis.PolisClientSecretRef("other-id"))
}
