// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SPCertificate is one platform SAML SP signing certificate. Only the PUBLIC
// certificate PEM (CertPEM) lives in the DB row; the private key is stored
// out-of-band in a k8s Secret, referenced by SecretRef (the data-key, equal to
// Serial). During graceful rotation exactly one row is Active while a
// just-rotated predecessor is retained — its RetiredAt set to now+overlap — so
// both keep signing/validating until the overlap window elapses.
type SPCertificate struct {
	ID        uuid.UUID
	Serial    string
	CertPEM   string
	SecretRef string
	Active    bool
	NotAfter  time.Time
	RetiredAt *time.Time
	CreatedAt time.Time
}

// InsertSPCertificate inserts a new SP certificate row. The caller supplies
// ID (uuid.New()) so it can address the row immediately (e.g. to flip it active
// during rotation) without a follow-up lookup. Only public material is stored;
// there is no column for the private key.
func (s *Store) InsertSPCertificate(ctx context.Context, c SPCertificate) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sp_certificates (id, serial, cert_pem, secret_ref, active, not_after)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		c.ID, c.Serial, c.CertPEM, c.SecretRef, c.Active, c.NotAfter)
	if err != nil {
		return mapPgError(err, ErrConflict)
	}
	return nil
}

// GetActiveSPCertificate returns the single active certificate. ErrNotFound
// when none is active (first boot, before EnsureInitial).
func (s *Store) GetActiveSPCertificate(ctx context.Context) (SPCertificate, error) {
	var c SPCertificate
	err := s.pool.QueryRow(ctx,
		`SELECT id, serial, cert_pem, secret_ref, active, not_after, retired_at, created_at
		 FROM sp_certificates WHERE active LIMIT 1`).
		Scan(&c.ID, &c.Serial, &c.CertPEM, &c.SecretRef, &c.Active, &c.NotAfter, &c.RetiredAt, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SPCertificate{}, ErrNotFound
	}
	if err != nil {
		return SPCertificate{}, err
	}
	return c, nil
}

// ListSPCertificates returns every certificate row (active, overlapping, and
// past-overlap) ordered oldest-first.
func (s *Store) ListSPCertificates(ctx context.Context) ([]SPCertificate, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, serial, cert_pem, secret_ref, active, not_after, retired_at, created_at
		 FROM sp_certificates ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SPCertificate{}
	for rows.Next() {
		var c SPCertificate
		if err := rows.Scan(&c.ID, &c.Serial, &c.CertPEM, &c.SecretRef, &c.Active, &c.NotAfter, &c.RetiredAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SetActiveSPCertificate makes id the sole active certificate. It clears the
// active flag on every other row first, then sets it on id, in one transaction
// so the single-active partial unique index is never transiently violated.
// ErrNotFound when id does not exist.
func (s *Store) SetActiveSPCertificate(ctx context.Context, id uuid.UUID) error {
	return s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE sp_certificates SET active = FALSE WHERE active AND id <> $1`, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx,
			`UPDATE sp_certificates SET active = TRUE WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// RetireOldSPCertificates schedules every not-yet-retired certificate other
// than keepID to retire at retiredAt (typically now+overlap). It leaves keepID
// (the new active cert) untouched and does not re-stamp rows already carrying a
// retired_at. Returns the number of rows scheduled.
func (s *Store) RetireOldSPCertificates(ctx context.Context, keepID uuid.UUID, retiredAt time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE sp_certificates SET retired_at = $2 WHERE id <> $1 AND retired_at IS NULL`,
		keepID, retiredAt)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
