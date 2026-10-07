// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package spkeys_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/Steward-GRC/steward-identity/internal/sso/spkeys"
)

// seedSecret returns an empty Secret to seed the fake clientset with — the
// deploy provisions the Secret out-of-band, so the Store never creates it.
func seedSecret(ns, name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Data:       map[string][]byte{},
	}
}

func TestK8sStore_PutGetRoundTrip(t *testing.T) {
	cs := fake.NewClientset(seedSecret("id-ns", "identity-sp-cert"))
	st := spkeys.NewK8sStore(cs, "id-ns", "identity-sp-cert")
	ctx := context.Background()

	require.NoError(t, st.PutKey(ctx, "12345", []byte("PEM-KEY-BYTES")))
	got, err := st.GetKey(ctx, "12345")
	require.NoError(t, err)
	require.Equal(t, []byte("PEM-KEY-BYTES"), got)
}

func TestK8sStore_GetMissingKey(t *testing.T) {
	cs := fake.NewClientset(seedSecret("id-ns", "identity-sp-cert"))
	st := spkeys.NewK8sStore(cs, "id-ns", "identity-sp-cert")
	_, err := st.GetKey(context.Background(), "absent")
	require.ErrorIs(t, err, spkeys.ErrKeyNotFound)
}

func TestK8sStore_MissingSecretIsNotKeyNotFound(t *testing.T) {
	st := spkeys.NewK8sStore(fake.NewClientset(), "id-ns", "identity-sp-cert")
	_, err := st.GetKey(context.Background(), "any")
	require.Error(t, err)
	require.NotErrorIs(t, err, spkeys.ErrKeyNotFound, "a missing Secret must not read as a missing key")
}

func TestK8sStore_DeleteKey(t *testing.T) {
	cs := fake.NewClientset(seedSecret("id-ns", "identity-sp-cert"))
	st := spkeys.NewK8sStore(cs, "id-ns", "identity-sp-cert")
	ctx := context.Background()
	require.NoError(t, st.PutKey(ctx, "a", []byte("1")))
	require.NoError(t, st.PutKey(ctx, "b", []byte("2")))

	require.NoError(t, st.DeleteKey(ctx, "a"))
	require.NoError(t, st.DeleteKey(ctx, "never-there"))

	_, err := st.GetKey(ctx, "a")
	require.ErrorIs(t, err, spkeys.ErrKeyNotFound)
	got, err := st.GetKey(ctx, "b")
	require.NoError(t, err)
	require.Equal(t, []byte("2"), got)
}

// TestK8sStore_OverlappingKeysCoexist proves the graceful-rotation invariant at
// the storage layer: the old serial's key stays retrievable while the new one
// is added, since each is a distinct data-key of the same Secret.
func TestK8sStore_OverlappingKeysCoexist(t *testing.T) {
	cs := fake.NewClientset(seedSecret("id-ns", "identity-sp-cert"))
	st := spkeys.NewK8sStore(cs, "id-ns", "identity-sp-cert")
	ctx := context.Background()

	require.NoError(t, st.PutKey(ctx, "old-serial", []byte("KEY-1")))
	require.NoError(t, st.PutKey(ctx, "new-serial", []byte("KEY-2")))

	k1, err := st.GetKey(ctx, "old-serial")
	require.NoError(t, err)
	require.Equal(t, []byte("KEY-1"), k1)
	k2, err := st.GetKey(ctx, "new-serial")
	require.NoError(t, err)
	require.Equal(t, []byte("KEY-2"), k2)
}
