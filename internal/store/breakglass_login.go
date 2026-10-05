// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// BreakGlassLoginEligible reports whether the account behind identifier may use
// the audited break-glass local login path when SSO is unavailable: the account
// must be privileged (root OR hold the site-admin role) AND actually hold a
// local credential (a local-account password or at least one registered
// WebAuthn passkey). A site-admin who is federated-only (SSO/JIT-provisioned,
// no local password or passkey) is deliberately NOT eligible — break-glass is
// a fallback for accounts that can authenticate without the IdP, not a
// privilege escalation for every site-admin. A regular user who happens to be
// local is also NOT eligible without the privileged role.
//
// identifier is matched case-insensitively against EITHER the email OR the
// username — the login form/gateway forwards whatever the operator typed, and
// the normal password login accepts both, so break-glass must too (matching by
// email only wrongly returned "unknown_user" when a root/site-admin typed their
// username).
//
// TOMBSTONED rows are excluded and report "unknown_user". This is
// the one lookup where a wrong answer hands out an audited login that bypasses
// the IdP, and a tombstoned privileged local account matched it and reported
// eligible=true/"ok". Adding the predicate also fixes a second defect: the query
// had no LIMIT, so with a tombstoned duplicate AND a live row on the same email
// QueryRow silently took whichever row Postgres returned first — eligibility was
// nondeterministic, and could report not_privileged for a real site-admin. The
// lookup is now explicitly the oldest LIVE match.
//
// reason is a machine string for logging/telemetry: "ok" | "not_privileged" |
// "no_local_credential" | "unknown_user".
func (s *Store) BreakGlassLoginEligible(ctx context.Context, identifier string) (bool, string, error) {
	var (
		isRoot      bool
		isSiteAdmin bool
		localAcct   bool
		passkeys    int
	)
	err := s.pool.QueryRow(ctx,
		`SELECT u.is_root,
		        EXISTS(SELECT 1 FROM user_roles r WHERE r.user_id = u.id AND r.role = 'site-admin'),
		        u.local_account,
		        (SELECT count(*) FROM user_webauthn_credentials w WHERE w.user_id = u.id)
		 FROM users u
		 WHERE (lower(u.email) = lower($1) OR lower(u.username) = lower($1))
		   AND u.deleted_at IS NULL
		 ORDER BY u.created_at ASC
		 LIMIT 1`, identifier).
		Scan(&isRoot, &isSiteAdmin, &localAcct, &passkeys)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "unknown_user", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("break-glass login eligibility: %w", err)
	}
	if !isRoot && !isSiteAdmin {
		return false, "not_privileged", nil
	}
	if !localAcct && passkeys == 0 {
		return false, "no_local_credential", nil
	}
	return true, "ok", nil
}
