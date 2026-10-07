// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package spkeys stores the SAML SP signing private key out-of-band from the
// database: the key material lives only in a Kubernetes Secret, keyed by the
// certificate serial. The DB row (see internal/store.SPCertificate) holds the
// PUBLIC certificate PEM and a secret_ref pointing at the data-key in this
// Secret; the private key never touches Postgres and is never logged.
package spkeys

import (
	"context"
	"errors"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Store persists and retrieves SP signing private keys by data-key (the cert
// serial). Implementations MUST NOT log key bytes.
type Store interface {
	// PutKey writes pemKey under dataKey, overwriting any existing value.
	PutKey(ctx context.Context, dataKey string, pemKey []byte) error
	// GetKey reads the PEM key stored under dataKey. It returns an error
	// wrapping ErrKeyNotFound when the Secret has no value for dataKey.
	GetKey(ctx context.Context, dataKey string) ([]byte, error)
	// DeleteKey removes dataKey from the Secret; a missing key is not an
	// error.
	DeleteKey(ctx context.Context, dataKey string) error
}

// ErrKeyNotFound means the Secret exists but holds no value under the key. A
// missing Secret or an API error is a different error, so a caller can tell
// "this key doesn't exist" from "the store couldn't be read".
var ErrKeyNotFound = errors.New("spkeys: key not found")

// k8sStore is a Store backed by a single Kubernetes Secret. Each serial is a
// data-key within that Secret's Data map, so overlapping-rotation keys coexist
// (old serial + new serial) until the old cert is retired.
type k8sStore struct {
	cs         kubernetes.Interface
	ns         string
	secretName string
}

// NewK8sStore returns a Store that reads/writes the private keys as data-keys
// of the named Secret in namespace ns. The Secret is expected to exist (the
// deploy provisions it out-of-band); PutKey Gets it, mutates one data-key, and
// Updates it in place rather than minting Secrets from the service.
func NewK8sStore(cs kubernetes.Interface, ns, secretName string) Store {
	return &k8sStore{cs: cs, ns: ns, secretName: secretName}
}

// PutKey Gets the backing Secret, sets Data[dataKey] to the PEM key, and
// Updates it. It never logs pemKey.
func (s *k8sStore) PutKey(ctx context.Context, dataKey string, pemKey []byte) error {
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("spkeys: get secret %s/%s: %w", s.ns, s.secretName, err)
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	// Copy so we never retain the caller's backing array in the Secret object.
	buf := make([]byte, len(pemKey))
	copy(buf, pemKey)
	sec.Data[dataKey] = buf
	if _, err := s.cs.CoreV1().Secrets(s.ns).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("spkeys: update secret %s/%s: %w", s.ns, s.secretName, err)
	}
	return nil
}

// GetKey reads Data[dataKey] from the backing Secret. It returns an error when
// the Secret is absent or has no value for dataKey.
func (s *k8sStore) GetKey(ctx context.Context, dataKey string) ([]byte, error) {
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("spkeys: secret %s/%s not found: %w", s.ns, s.secretName, err)
		}
		return nil, fmt.Errorf("spkeys: get secret %s/%s: %w", s.ns, s.secretName, err)
	}
	v, ok := sec.Data[dataKey]
	if !ok {
		return nil, fmt.Errorf("%w: %q in secret %s/%s", ErrKeyNotFound, dataKey, s.ns, s.secretName)
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// DeleteKey removes dataKey from the Secret's data; a key that isn't there
// leaves the Secret untouched.
func (s *k8sStore) DeleteKey(ctx context.Context, dataKey string) error {
	sec, err := s.cs.CoreV1().Secrets(s.ns).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("spkeys: get secret %s/%s: %w", s.ns, s.secretName, err)
	}
	if _, ok := sec.Data[dataKey]; !ok {
		return nil
	}
	delete(sec.Data, dataKey)
	if _, err := s.cs.CoreV1().Secrets(s.ns).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("spkeys: update secret %s/%s: %w", s.ns, s.secretName, err)
	}
	return nil
}
