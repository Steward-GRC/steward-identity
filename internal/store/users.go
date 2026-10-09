// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetUser fetches a user by platform id and hydrates roles + groups.
func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	u := User{ID: id}
	var username *string
	err := s.pool.QueryRow(ctx,
		`SELECT external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, onboarding_complete, first_name, last_name, timezone, locale, deleted_at, merged_into_user_id
		 FROM users WHERE id = $1`, id,
	).Scan(&u.ExternalSubject, &username, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.OnboardingComplete, &u.FirstName, &u.LastName, &u.Timezone, &u.Locale, &u.DeletedAt, &u.MergedIntoUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user: %w", err)
	}
	if username != nil {
		u.Username = *username
	}
	if err := s.hydrateUser(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// GetUserByExternalSubject is the lookup used by ResolveClaims. Returns
// ErrNotFound if no user is mapped to the given subject; the caller then
// creates the account.
func (s *Store) GetUserByExternalSubject(ctx context.Context, sub string) (User, error) {
	var u User
	var username *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, onboarding_complete, first_name, last_name, timezone, locale, deleted_at, merged_into_user_id
		 FROM users WHERE external_subject = $1`, sub,
	).Scan(&u.ID, &u.ExternalSubject, &username, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.OnboardingComplete, &u.FirstName, &u.LastName, &u.Timezone, &u.Locale, &u.DeletedAt, &u.MergedIntoUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by sub: %w", err)
	}
	if username != nil {
		u.Username = *username
	}
	if err := s.hydrateUser(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// GetUserByEmail is the exact, case-insensitive lookup backing the
// GetUserByEmail RPC: the gateway's Kratos
// local-login backend resolves the platform user by email since Kratos's
// opaque session_token carries no external_subject for GetUserByExternalSubject
// to key on. Unlike GetLocalUserByEmail (otp.go), this is NOT restricted to
// local_account rows — any platform user (local or federated) with a matching
// email resolves. If more than one row somehow shares an email (not
// uniqueness-enforced at the schema level), the oldest wins, matching
// GetLocalUserByEmail's tie-break. Returns ErrNotFound when no row matches.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	var username *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, onboarding_complete, first_name, last_name, timezone, locale, deleted_at, merged_into_user_id
		 FROM users WHERE lower(email) = lower($1)
		 ORDER BY created_at ASC LIMIT 1`, email,
	).Scan(&u.ID, &u.ExternalSubject, &username, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.OnboardingComplete, &u.FirstName, &u.LastName, &u.Timezone, &u.Locale, &u.DeletedAt, &u.MergedIntoUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	if username != nil {
		u.Username = *username
	}
	if err := s.hydrateUser(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// getLiveUserByEmail is GetUserByEmail restricted to LIVE accounts — the
// variant every auth/adoption decision needs.
//
// It is deliberately a SEPARATE method rather than a filter on GetUserByEmail:
// that function backs the gateway's user-label resolution, and tombstoned user
// ids are legitimately referenced by historical audit, acknowledgment and
// approval rows, so filtering it would print raw UUIDs across the audit history
// . SEARCH and LOOKUP-FOR-AUTH exclude tombstones;
// RESOLVE-FOR-DISPLAY does not.
//
// Unexported: callers inside the store use it directly, and the one handler that
// needs it (the JIT-disabled SSO branch) goes through FindLiveUserByEmail.
func (s *Store) getLiveUserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	var username *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, onboarding_complete, first_name, last_name, timezone, locale, deleted_at, merged_into_user_id
		 FROM users WHERE lower(email) = lower($1) AND deleted_at IS NULL
		 ORDER BY created_at ASC LIMIT 1`, email,
	).Scan(&u.ID, &u.ExternalSubject, &username, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.OnboardingComplete, &u.FirstName, &u.LastName, &u.Timezone, &u.Locale, &u.DeletedAt, &u.MergedIntoUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get live user by email: %w", err)
	}
	if username != nil {
		u.Username = *username
	}
	if err := s.hydrateUser(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// FindLiveUserByEmail is the exported form of getLiveUserByEmail, for handlers
// that must resolve a login principal by email and must not accept a tombstone
// . Use GetUserByEmail when the answer is a display label.
func (s *Store) FindLiveUserByEmail(ctx context.Context, email string) (User, error) {
	return s.getLiveUserByEmail(ctx, email)
}

// JITProvision inserts a brand-new user and emits `user.created` +
// `user.login.success` audit events. Both happen in one transaction so the
// audit rows are durable iff the user actually committed. Reader access is
// implicit — no stored role is inserted.
//
// If a row with the same external_subject was created concurrently by another
// gateway pod the function returns the existing user (ErrConflict is mapped
// upstream to a normal fetch).
func (s *Store) JITProvision(ctx context.Context, externalSub, email, name string) (User, error) {
	return s.JITProvisionWithNames(ctx, externalSub, email, name, "", "")
}

// JITProvisionWithNames is JITProvision plus the structured given/family name
// forwarded by the gateway from the IdP claims. firstName/lastName may be empty
// when the IdP provided none; when the display `name` is empty but the parts are
// present, `name` is composed from them so it stays populated.
func (s *Store) JITProvisionWithNames(ctx context.Context, externalSub, email, name, firstName, lastName string) (User, error) {
	// Display name is DERIVED from the structured parts: whenever a given/family
	// name is available, name = "first last". Only when neither part is present
	// (e.g. the IdP forwarded a bare `name` claim) is the forwarded name kept.
	if firstName != "" || lastName != "" {
		name = strings.TrimSpace(firstName + " " + lastName)
	}
	// Derive a login username from the email local-part for SSO/JIT users (e.g.
	// "alice@example.org" -> "alice"). The users_lower_username_uniq
	// partial index enforces case-insensitive uniqueness, so we pick the first
	// free base/base2/base3… candidate and retry on the rare insert race.
	base := deriveUsernameBase(email)
	const maxAttempts = 6
	var lastErr error
	for range maxAttempts {
		var username *string
		if base != "" {
			cand, err := s.nextAvailableUsername(ctx, base)
			if err != nil {
				return User{}, err
			}
			username = &cand
		}
		u, err := s.jitProvisionOnce(ctx, externalSub, email, name, firstName, lastName, username)
		if err == nil {
			return u, nil
		}
		// A unique violation here can only be the username index (external_subject
		// is handled by ON CONFLICT below); recompute the suffix and retry.
		if username != nil && isUniqueViolation(err) {
			lastErr = err
			continue
		}
		return User{}, err
	}
	return User{}, fmt.Errorf("insert user: could not derive a unique username: %w", lastErr)
}

// jitProvisionOnce performs one JIT insert attempt inside a transaction. A nil
// username inserts SQL NULL (the historical federated-user shape); a non-nil
// username sets the derived login username. external_subject collisions are
// absorbed by ON CONFLICT DO UPDATE and never touch username.
func (s *Store) jitProvisionOnce(ctx context.Context, externalSub, email, name, firstName, lastName string, username *string) (User, error) {
	var u User
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var err error
		u.ExternalSubject = externalSub
		u.Email = email
		u.Name = name
		u.FirstName = firstName
		u.LastName = lastName
		// On re-login the IdP name parts fill only when the stored value is EMPTY —
		// once a name is set (by the IdP earlier or by the user's own edit via
		// UpdateMyProfile), a later SSO login must not clobber it
		// ("fill only when empty"). Email still refreshes.
		err = tx.QueryRow(ctx,
			`INSERT INTO users (external_subject, email, name, username, first_name, last_name) VALUES ($1, $2, $3, $4, $5, $6)
			   ON CONFLICT (external_subject) WHERE external_subject <> '' DO UPDATE SET email = EXCLUDED.email, name = CASE WHEN users.name = '' THEN EXCLUDED.name ELSE users.name END, first_name = CASE WHEN users.first_name = '' THEN EXCLUDED.first_name ELSE users.first_name END, last_name = CASE WHEN users.last_name = '' THEN EXCLUDED.last_name ELSE users.last_name END, updated_at = now()
			 RETURNING id, fcm_token, enabled, created_at, updated_at, name, first_name, last_name`,
			externalSub, email, name, username, firstName, lastName,
		).Scan(&u.ID, &u.FCMToken, &u.Enabled, &u.CreatedAt, &u.UpdatedAt, &u.Name, &u.FirstName, &u.LastName)
		if err != nil {
			return fmt.Errorf("insert user: %w", err)
		}

		if err := s.emitAuditTx(ctx, tx, "user.created", &u.ID, "", &u.ID, nil, map[string]any{"email": email}); err != nil {
			return err
		}
		if err := s.emitAuditTx(ctx, tx, "user.login.success", &u.ID, "", &u.ID, nil, map[string]any{}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return User{}, err
	}

	return s.GetUser(ctx, u.ID)
}

// JITProvisionByEmail resolves a platform user by email, JIT-provisioning a
// federated (Polis/SSO) row when none exists. It is the by-email counterpart to
// JITProvisionWithNames' subject-keyed provisioning: federated SSO users arrive
// through an opaque broker token with no subject, so the row is keyed
// on email and created with an EMPTY external_subject (matching the empty-subject
// shape a pre-created local row carries before adoption) and local_account=false
// (they are IdP-federated, not in-app managed). enabled and is_root take the
// column defaults (enabled=true, is_root=false). The username is derived from
// the email local-part exactly like JITProvisionWithNames.
//
// It returns (user, created, err): created is true only when this call inserted
// a brand-new row, so the handler can scope its sso.account_provisioned welcome
// to a genuine first provision. When a user with the given email already exists
// it is returned unchanged (idempotent; oldest-wins on a duplicate, matching
// GetUserByEmail).
//
// Concurrency: email is NOT uniqueness-enforced at the schema level (see
// GetUserByEmail), so two simultaneous first-logins for the same address could
// otherwise both insert. A Postgres transaction-scoped advisory lock keyed on
// lower(email) serializes provisioning per address; the loser re-reads the
// winner's committed row and reports created=false.
func (s *Store) JITProvisionByEmail(ctx context.Context, email, firstName, lastName string) (User, bool, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return User{}, false, fmt.Errorf("%w: email required", ErrInvalid)
	}
	// Fast path: already provisioned — no lock, no write.
	//
	// getLiveUserByEmail, NOT GetUserByEmail. GetUserByEmail is a
	// RESOLVE path and is deliberately tombstone-blind so audit labels keep
	// working, and it tie-breaks `ORDER BY created_at ASC` — so a deleted older
	// row was actively PREFERRED over a live newer one and handed straight to
	// the federated login flow. Filtering only the in-lock recheck below would
	// have fixed nothing, because this lookup shadows it.
	if u, err := s.getLiveUserByEmail(ctx, email); err == nil {
		return u, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return User{}, false, err
	}
	// Slow path: create under a per-email advisory lock, retrying the username
	// derivation on the rare insert race (mirrors JITProvisionWithNames).
	base := deriveUsernameBase(email)
	const maxAttempts = 6
	var lastErr error
	for range maxAttempts {
		var username *string
		if base != "" {
			cand, err := s.nextAvailableUsername(ctx, base)
			if err != nil {
				return User{}, false, err
			}
			username = &cand
		}
		u, created, err := s.jitProvisionByEmailOnce(ctx, email, firstName, lastName, username)
		if err == nil {
			return u, created, nil
		}
		if username != nil && isUniqueViolation(err) {
			lastErr = err
			continue
		}
		return User{}, false, err
	}
	return User{}, false, fmt.Errorf("insert federated user: could not derive a unique username: %w", lastErr)
}

// jitProvisionByEmailOnce performs one email-keyed JIT insert attempt. It takes
// a transaction-scoped advisory lock on lower(email) so concurrent provisions
// for the same address serialize, re-checks for an existing row inside the lock
// (the winner of a race has already committed its row by the time we hold the
// lock), and only inserts when none exists. The federated row carries an EMPTY
// external_subject and local_account=false; the display name is derived from the
// given/family parts. user.created + user.login.success audit events are emitted
// in the same transaction, mirroring jitProvisionOnce.
func (s *Store) jitProvisionByEmailOnce(ctx context.Context, email, firstName, lastName string, username *string) (User, bool, error) {
	var existingID uuid.UUID
	var u User
	found := false
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		found = false
		var err error
		// Serialize concurrent provisions for this email. The lock is released when
		// the transaction ends (commit or rollback); hashtext gives a stable 32-bit
		// key from the normalized address.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext(lower($1)))`, email); err != nil {
			return fmt.Errorf("advisory lock: %w", err)
		}

		// Re-check inside the lock: a concurrent winner may have created the row
		// between the fast-path miss and our acquiring the lock. READ COMMITTED means
		// this statement sees the winner's committed insert.
		// `deleted_at IS NULL`: the recheck must agree with the fast path above, or a
		// tombstone would be adopted by whichever of the two saw it.
		err = tx.QueryRow(ctx,
			`SELECT id FROM users WHERE lower(email) = lower($1) AND deleted_at IS NULL
			 ORDER BY created_at ASC LIMIT 1`, email,
		).Scan(&existingID)
		if err == nil {
			found = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("recheck user by email: %w", err)
		}

		// Display name is DERIVED from the structured parts when present, matching
		// jitProvisionOnce; empty is tolerated (the user fills it in at onboarding).
		name := strings.TrimSpace(firstName + " " + lastName)

		u.Email = email
		u.Name = name
		u.FirstName = firstName
		u.LastName = lastName
		err = tx.QueryRow(ctx,
			`INSERT INTO users (external_subject, email, name, username, first_name, last_name, local_account)
			 VALUES ('', $1, $2, $3, $4, $5, false)
			 RETURNING id, fcm_token, enabled, created_at, updated_at`,
			email, name, username, firstName, lastName,
		).Scan(&u.ID, &u.FCMToken, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			return fmt.Errorf("insert federated user: %w", err)
		}

		if err := s.emitAuditTx(ctx, tx, "user.created", &u.ID, "", &u.ID, nil,
			map[string]any{"email": email, "federated": true, "jit_by_email": true}); err != nil {
			return err
		}
		if err := s.emitAuditTx(ctx, tx, "user.login.success", &u.ID, "", &u.ID, nil, map[string]any{}); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return User{}, false, err
	}
	if found {
		existing, err := s.GetUser(ctx, existingID)
		return existing, false, err
	}

	full, err := s.GetUser(ctx, u.ID)
	if err != nil {
		return User{}, false, err
	}
	return full, true, nil
}

// deriveUsernameBase returns the lowercased local-part (text before '@') of an
// email, to seed a derived login username. Returns "" when email is empty so
// the caller leaves username NULL (the historical federated-user shape).
func deriveUsernameBase(email string) string {
	local := email
	if before, _, ok := strings.Cut(email, "@"); ok {
		local = before
	}
	return strings.ToLower(strings.TrimSpace(local))
}

// nextAvailableUsername returns the first of base, base2, base3, … whose
// lower(username) is not already taken. Case-insensitive to match the
// users_lower_username_uniq index. The insert path still guards the race.
func (s *Store) nextAvailableUsername(ctx context.Context, base string) (string, error) {
	for n := 1; n <= 1000; n++ {
		cand := base
		if n > 1 {
			cand = fmt.Sprintf("%s%d", base, n)
		}
		var exists bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE lower(username) = lower($1))`, cand,
		).Scan(&exists); err != nil {
			return "", fmt.Errorf("check username availability: %w", err)
		}
		if !exists {
			return cand, nil
		}
	}
	return "", fmt.Errorf("could not derive a unique username for base %q", base)
}

// UpdateUserProfile updates the email, name, structured first/last name, and the
// timezone/locale identity facts for an existing user and emits a
// `user.profile.updated` audit event. Callers pass
// the full effective value for every field (the store does not merge). The
// update and audit are
// committed atomically. Callers should only invoke this when at least one
// field has actually changed; the method does not guard against no-ops itself.
func (s *Store) UpdateUserProfile(ctx context.Context, id uuid.UUID, email, name, firstName, lastName, timezone, locale string) (User, error) {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE users SET email = $2, name = $3, first_name = $4, last_name = $5, timezone = $6, locale = $7, updated_at = now() WHERE id = $1`,
			id, email, name, firstName, lastName, timezone, locale)
		if err != nil {
			return fmt.Errorf("update profile: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.profile.updated", &id, "", &id, nil,
			map[string]any{"email": email, "name": name, "first_name": firstName, "last_name": lastName, "timezone": timezone, "locale": locale}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// UpdateUsername sets the login username for a user and emits a
// `user.username.updated` audit event. The username is validated for
// case-insensitive uniqueness by the users_lower_username_uniq index; a
// collision is mapped to ErrConflict. An empty username is rejected as
// ErrInvalid (callers wanting to clear a username are not supported here).
func (s *Store) UpdateUsername(ctx context.Context, id uuid.UUID, username string) (User, error) {
	if strings.TrimSpace(username) == "" {
		return User{}, fmt.Errorf("%w: username must not be empty", ErrInvalid)
	}
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE users SET username = $2, updated_at = now() WHERE id = $1`, id, username)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: username %q already exists", ErrConflict, username)
			}
			return fmt.Errorf("update username: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.username.updated", &id, "", &id, nil,
			map[string]any{"username": username}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// CompleteOnboarding records the user's terms acceptance and marks their
// first-run onboarding done, emitting a `user.onboarding.completed` audit event.
// It is idempotent: terms_accepted_at is only stamped on the first acceptance
// (COALESCE keeps the original timestamp), and re-completing is a harmless
// no-op flip. Returns the updated user.
func (s *Store) CompleteOnboarding(ctx context.Context, id uuid.UUID) (User, error) {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE users
			    SET onboarding_complete = TRUE,
			        terms_accepted_at   = COALESCE(terms_accepted_at, now()),
			        updated_at          = now()
			  WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("complete onboarding: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "user.onboarding.completed", &id, "", &id, nil,
			map[string]any{}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// MarkEmailVerified records that user id proved control of email — the
// persistence side of the public verify-email link. It is idempotent: verifying an already-verified address performs
// no second write and reports alreadyVerified=true.
//
// email is re-checked (case-insensitively) against the account's CURRENT
// address inside the transaction: a token minted for a since-changed address
// resolves to a real user but a stale email, and MUST NOT be honored, so that
// case returns ErrEmailMismatch. A missing user returns ErrNotFound.
func (s *Store) MarkEmailVerified(ctx context.Context, id uuid.UUID, email string) (alreadyVerified bool, err error) {
	var currentEmail string
	var verified bool
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`SELECT email, email_verified FROM users WHERE id = $1`, id,
		).Scan(&currentEmail, &verified)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("load user for email-verify: %w", err)
		}
		if !strings.EqualFold(strings.TrimSpace(currentEmail), strings.TrimSpace(email)) {
			return ErrEmailMismatch
		}
		if verified {
			// Idempotent replay: already verified, no second write, no audit event.
			return nil
		}

		if _, err := tx.Exec(ctx,
			`UPDATE users
			    SET email_verified    = TRUE,
			        email_verified_at = now(),
			        updated_at        = now()
			  WHERE id = $1`, id); err != nil {
			return fmt.Errorf("mark email verified: %w", err)
		}
		if err := s.emitAuditTx(ctx, tx, "user.email.verified", &id, "", &id, nil,
			map[string]any{"email": currentEmail}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return false, err
	}
	return verified, nil
}

// SetEnabled flips users.enabled, emits the matching audit event, and returns
// the updated user. Idempotent: re-setting the same value is a no-op (except
// it always emits an event for the audit lane).
func (s *Store) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool, actor *uuid.UUID, actorExternal string) (User, error) {
	// A root admin cannot be disabled (lockout-safe). Revoke root
	// first to demote it.
	if !enabled {
		root, err := s.isRoot(ctx, id)
		if err != nil {
			return User{}, err
		}
		if root {
			return User{}, fmt.Errorf("%w: cannot disable the root account", ErrRootProtected)
		}
	}
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE users SET enabled = $2, updated_at = now() WHERE id = $1`, id, enabled)
		if err != nil {
			return fmt.Errorf("update enabled: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		event := "user.disabled"
		if enabled {
			event = "user.enabled"
		}
		if err := s.emitAuditTx(ctx, tx, event, actor, actorExternal, &id, nil, map[string]any{}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// DeleteUser soft-deletes a user in one transaction: it stamps deleted_at,
// disables the account and deletes the user's identity access rows (group
// memberships, identity provider groups, roles, permissions, per-policy
// overrides, break-glass grants). Sign-in sessions live in the sign-in
// service, so the caller revokes them.
//
// It NEVER deletes a policy: identity holds no policy records — policies live in
// the core service and REMAIN (orphaned) after this call for an admin to
// re-assign. The users row is deliberately retained (soft delete) so historical
// audit attribution stays intact; MFA/webauthn/OTP rows are left inert
// (login is already blocked by enabled=false). The root account is protected.
//
// Idempotent: a second call keeps the first deleted_at and deletes nothing
// more.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID, actor *uuid.UUID, actorExternal string) (User, error) {
	// A root admin cannot be deleted; revoke root first, which the last
	// root admin can't lose.
	root, err := s.isRoot(ctx, id)
	if err != nil {
		return User{}, err
	}
	if root {
		return User{}, fmt.Errorf("%w: cannot delete the root account", ErrRootProtected)
	}

	var email string
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, id).Scan(&email); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("load user: %w", err)
		}

		// Keep the row for attribution; COALESCE keeps the first delete time.
		if _, err := tx.Exec(ctx,
			`UPDATE users SET deleted_at = COALESCE(deleted_at, now()), enabled = false, updated_at = now() WHERE id = $1`,
			id); err != nil {
			return fmt.Errorf("soft-delete user: %w", err)
		}

		for _, table := range deletedAccessTables {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE user_id = $1`, id); err != nil {
				return fmt.Errorf("delete %s: %w", table, err)
			}
		}

		return s.emitAuditTx(ctx, tx, "user.deleted", actor, actorExternal, &id, nil,
			map[string]any{"email": email})
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, id)
}

// ListUsersByEmail returns up to limit users whose email, username, first name,
// last name, or "first last" display name contains the given substring
// (case-insensitive, ILIKE), in (email, id) ascending order. Despite the
// historical name, the match is NOT email-only: the user-picker typeahead
// backing every RACI/admin user select needs to resolve on a person's name
// (given/family) and login, not just the email address. The
// cursor is a stable encoding of the last returned (email, id) pair so a
// concurrent insert sorted before the cursor doesn't shift the next page.
//
// Tombstoned rows (deleted_at IS NOT NULL — soft-deleted via DeleteUser, or
// merged away via TombstoneMergedSource) are EXCLUDED. A picker
// that offers a merged-away account lets an admin choose it as a merge target,
// migrating live records onto a deleted account. The exclusion is deliberately
// asymmetric with the resolve path: GetUser / GetUserByEmail / GetUserByUsername
// still return tombstoned rows, because historical audit, acknowledgment and
// approval records legitimately reference merged-away user ids and the
// gateway's resolveUserLabels turns those ids into display names. Filtering
// there would print raw UUIDs across the audit history.
// SEARCH EXCLUDES; RESOLVE DOES NOT.
//
// The exclusion is opt-OUT-able for exactly one caller: the admin directory
// view, via SearchUsers with UserSearchOpts.IncludeDeleted.
// Search's exclusion left NO surface in the product listing a soft-deleted
// account, so an admin could not see that one had existed or which account it
// had been merged into. This 5-argument form never sets it and never will —
// it is the picker's entry point.
//
// enabled = false is deliberately NOT filtered. A disabled duplicate with
// deleted_at IS NULL is the canonical account-merge SOURCE, and production
// holds real disabled duplicates on SSO-locked domains, so hiding them would
// break the merge feature's main use case. Only deleted_at decides visibility.
//
// An empty substring matches every live row. limit==0 falls back to 50;
// values > 200 are clamped to 200 by the handler (the store still honours
// whatever is passed). cursor is opaque to callers; the handler is
// responsible for validating / propagating it.
//
// The returned cursor is empty when the page is the final one (i.e. fewer
// rows than the limit came back).
func (s *Store) ListUsersByEmail(ctx context.Context, substring string, limit int, cursorEmail string, cursorID uuid.UUID) ([]User, error) {
	return s.SearchUsers(ctx, UserSearchOpts{
		Substring:   substring,
		Limit:       limit,
		CursorEmail: cursorEmail,
		CursorID:    cursorID,
	})
}

// UserSearchOpts are the inputs to SearchUsers. It is a struct rather than
// positional parameters so IncludeDeleted could be added without
// touching the sixteen existing ListUsersByEmail call sites — and, more
// importantly, so the dangerous option can only ever be set BY NAME. A
// positional bool is exactly the kind of argument a picker acquires by
// copy-paste, and offering a merged-away account in a picker is the defect
// this guards against.
type UserSearchOpts struct {
	Substring   string
	Limit       int // <=0 falls back to 50
	CursorEmail string
	CursorID    uuid.UUID
	// IncludeDeleted also returns tombstoned (soft-deleted / merged-away)
	// accounts, each carrying DeletedAt and — when merged away rather than
	// deleted outright — MergedIntoUserID.
	//
	// Set it ONLY for the admin directory view, whose purpose is to show that an
	// account existed and where its records went. NEVER for the
	// typeahead: a picker that offers a tombstone lets an admin choose it as a
	// merge or RACI target and migrate live records onto a deleted account.
	// Callers that set it MUST render tombstoned rows as closed/merged and MUST
	// NOT offer them as a selectable target.
	IncludeDeleted bool
}

// SearchUsers is the full form of ListUsersByEmail. See that function's doc for
// the match semantics, the cursor, and why `enabled` is deliberately not
// filtered; see UserSearchOpts.IncludeDeleted for the one option this adds.
func (s *Store) SearchUsers(ctx context.Context, opts UserSearchOpts) ([]User, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	substring, cursorEmail, cursorID := opts.Substring, opts.CursorEmail, opts.CursorID
	// We use a two-dimensional cursor (email, id) so duplicate-email rows
	// don't cause the cursor to skip rows. The `($2, $3)` tuple comparison
	// is supported natively by Postgres on B-tree columns and lets us stay
	// within a single index scan.
	//
	// The match widens across the identifier columns: email, username (NULL for
	// federated rows — ILIKE against NULL yields NULL, i.e. no match, which is
	// correct), first_name / last_name, and the composed "first last" display
	// name so a full-name query ("ivan ive") resolves too. All comparisons are
	// case-insensitive and fully parameterized. first_name/last_name are
	// NOT NULL DEFAULT '' so the concat is always well-formed.
	//
	// `($5 OR deleted_at IS NULL)` sits alongside the match, before the cursor
	// comparison and before LIMIT, so tombstones are gone from the row set the
	// keyset walks. Live rows therefore keep their (email, id) order and the
	// cursor neither skips nor repeats one when a tombstone is interleaved. With
	// IncludeDeleted the tombstones are simply IN that row set, so the same
	// argument holds for the wider result — the predicate moves rows in or out
	// of the set the keyset walks, it never reorders it.
	rows, err := s.pool.Query(ctx, `
		SELECT id, external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, onboarding_complete, first_name, last_name, timezone, locale, deleted_at, merged_into_user_id
		  FROM users
		 WHERE ($1 = '' OR email ILIKE '%' || $1 || '%'
		                OR username ILIKE '%' || $1 || '%'
		                OR first_name ILIKE '%' || $1 || '%'
		                OR last_name ILIKE '%' || $1 || '%'
		                OR (first_name || ' ' || last_name) ILIKE '%' || $1 || '%')
		   AND ($5 OR deleted_at IS NULL)
		   AND ($2 = '' OR (email, id) > ($2, $3))
		 ORDER BY email ASC, id ASC
		 LIMIT $4`,
		substring, cursorEmail, cursorID, limit, opts.IncludeDeleted)
	if err != nil {
		return nil, fmt.Errorf("list users by email: %w", err)
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var username *string
		if err := rows.Scan(&u.ID, &u.ExternalSubject, &username, &u.Email, &u.Name, &u.FCMToken,
			&u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.OnboardingComplete, &u.FirstName, &u.LastName, &u.Timezone, &u.Locale,
			&u.DeletedAt, &u.MergedIntoUserID); err != nil {
			return nil, err
		}
		if username != nil {
			u.Username = *username
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Hydrate all collections per user. Same N+K*N tradeoff as ListUsersInGroup.
	for i := range users {
		if err := s.hydrateUser(ctx, &users[i]); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// PreCreateLocalUser inserts a local-account row with local_account=true,
// external_subject=”, and the given username/email/name. The external_subject
// is empty until the first federated login "adopts" this row.
// A `user.created` audit event is emitted atomically. Returns ErrConflict if a
// local user with the same username (case-insensitive) already exists.
func (s *Store) PreCreateLocalUser(ctx context.Context, username, email, name string) (User, error) {
	var u User
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var err error
		u.Username = username
		u.Email = email
		u.Name = name
		u.LocalAccount = true
		err = tx.QueryRow(ctx,
			`INSERT INTO users (external_subject, username, email, name, local_account)
			 VALUES ('', $1, $2, $3, true)
			 RETURNING id, fcm_token, enabled, is_root, created_at, updated_at`,
			username, email, name,
		).Scan(&u.ID, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: username %q already exists", ErrConflict, username)
			}
			return fmt.Errorf("insert local user: %w", err)
		}

		if err := s.emitAuditTx(ctx, tx, "user.created", &u.ID, "", &u.ID, nil,
			map[string]any{"email": email, "username": username, "local": true}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, u.ID)
}

// GetUserByUsername returns the local-account user with the given username
// (case-insensitive). Returns ErrNotFound if no such user exists.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	var un *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, onboarding_complete, first_name, last_name, timezone, locale, deleted_at, merged_into_user_id
		 FROM users WHERE lower(username) = lower($1) AND username IS NOT NULL`, username,
	).Scan(&u.ID, &u.ExternalSubject, &un, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.OnboardingComplete, &u.FirstName, &u.LastName, &u.Timezone, &u.Locale, &u.DeletedAt, &u.MergedIntoUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by username: %w", err)
	}
	if un != nil {
		u.Username = *un
	}
	if err := s.hydrateUser(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// FindAdoptableLocalUser looks for a local_account row with an empty
// external_subject that matches the given email (case-insensitive) OR the
// given username (case-insensitive). It returns (user, true, nil) on a match,
// (User{}, false, nil) when no adoptable row exists, or (User{}, false, err)
// on a database error. Both email and username hints are optional (pass "" to
// skip a particular hint). The email hint is tried first; the username hint is
// a fallback for callers whose token email differs from what was pre-registered.
//
// TOMBSTONED rows are never adoptable. A soft-deleted or
// merged-away local account keeps its email, username and empty
// external_subject, so it still matched the adoption predicate; an SSO login
// could then be pointed at a record that had already been merged away and whose
// data now belongs to a different user. It failed closed only because both
// tombstone writers also set enabled = false and the downstream auth checks
// reject a disabled account — a side effect, not a check. The filter is applied
// in findAdoptableByField, which also LIMITs to the oldest LIVE match so a
// tombstoned duplicate can no longer shadow the live row it was merged into.
func (s *Store) FindAdoptableLocalUser(ctx context.Context, email, username string) (User, bool, error) {
	// Try email match first (most reliable identifier).
	if email != "" {
		u, err := s.findAdoptableByField(ctx, `lower(email) = lower($1) AND local_account = true AND external_subject = ''`, email)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return User{}, false, err
		}
		if err == nil {
			return u, true, nil
		}
	}
	// Fall back to username match.
	if username != "" {
		u, err := s.findAdoptableByField(ctx, `lower(username) = lower($1) AND local_account = true AND external_subject = ''`, username)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return User{}, false, err
		}
		if err == nil {
			return u, true, nil
		}
	}
	return User{}, false, nil
}

// findAdoptableByField runs one adoption lookup. The `AND deleted_at IS NULL`
// predicate lives HERE rather than in the caller-supplied WHERE so that no
// present or future call site can forget it: adoption is the one
// path where resolving a tombstone hands a federated login an account whose
// records now belong to somebody else.
func (s *Store) findAdoptableByField(ctx context.Context, where string, arg string) (User, error) {
	var u User
	var un *string
	err := s.pool.QueryRow(ctx,
		`SELECT id, external_subject, username, email, name, fcm_token, enabled, is_root, local_account, created_at, updated_at, onboarding_complete, first_name, last_name, timezone, locale, deleted_at, merged_into_user_id
		 FROM users WHERE (`+where+`) AND deleted_at IS NULL
		 ORDER BY created_at ASC LIMIT 1`,
		arg,
	).Scan(&u.ID, &u.ExternalSubject, &un, &u.Email, &u.Name, &u.FCMToken, &u.Enabled, &u.IsRoot, &u.LocalAccount, &u.CreatedAt, &u.UpdatedAt, &u.OnboardingComplete, &u.FirstName, &u.LastName, &u.Timezone, &u.Locale, &u.DeletedAt, &u.MergedIntoUserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("find adoptable user: %w", err)
	}
	if un != nil {
		u.Username = *un
	}
	if err := s.hydrateUser(ctx, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// AdoptLocalUser sets the external_subject on a pre-created local row,
// linking the identity-provider account to the in-app row. The update and a
// `user.adopted` audit event are committed atomically.
//
// The row must have an empty external_subject (i.e. not yet adopted); passing
// a non-existent id returns ErrNotFound. When RowsAffected == 0 because
// another concurrent call already won the race, the function returns
// ErrConflict so the caller can fall through to GetUserByExternalSubject and
// resolve the correct row for its own token.
func (s *Store) AdoptLocalUser(ctx context.Context, id uuid.UUID, externalSubject string) error {
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		// Adopting a pre-created local row links an ALREADY-EXISTING account to its
		// federated identity — the user is not new, so they must not be pushed
		// through onboarding. Mark them onboarded as part of the adopt. Pre-created
		// local rows always carry a username, so none is derived here.
		tag, err := tx.Exec(ctx,
			`UPDATE users SET external_subject = $2, onboarding_complete = TRUE, updated_at = now()
			 WHERE id = $1 AND external_subject = ''`,
			id, externalSubject)
		if err != nil {
			return fmt.Errorf("adopt local user: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Either the id doesn't exist or the row was already adopted
			// (concurrent race). Distinguish the two.
			var exists bool
			if scanErr := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, id).Scan(&exists); scanErr != nil {
				return fmt.Errorf("adopt local user check: %w", scanErr)
			}
			if !exists {
				return ErrNotFound
			}
			// Already adopted by a concurrent call — signal the caller to look up
			// the row by its own external_subject instead of by ID.
			return ErrConflict
		}
		if err := s.emitAuditTx(ctx, tx, "user.adopted", &id, externalSubject, &id, nil,
			map[string]any{"external_subject": externalSubject}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

// PreCreateLocalUserRoot creates a local root account with is_root=true,
// local_account=true, external_subject=”, and the given username/email/name.
// It mirrors PreCreateLocalUser but sets is_root=true and emits a
// user.bootstrap_root audit event. Used exclusively by BootstrapRoot.
func (s *Store) PreCreateLocalUserRoot(ctx context.Context, username, email, name string) (User, error) {
	var u User
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := lockRootSet(ctx, tx); err != nil {
			return err
		}
		var rootExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE is_root)`).Scan(&rootExists); err != nil {
			return fmt.Errorf("root exists check: %w", err)
		}
		if rootExists {
			return fmt.Errorf("%w: a root admin already exists", ErrConflict)
		}
		var err error
		u.Username = username
		u.Email = email
		u.Name = name
		u.LocalAccount = true
		u.IsRoot = true
		err = tx.QueryRow(ctx,
			`INSERT INTO users (external_subject, username, email, name, local_account, is_root)
			 VALUES ('', $1, $2, $3, true, true)
			 RETURNING id, name, fcm_token, enabled, created_at, updated_at`,
			username, email, name,
		).Scan(&u.ID, &u.Name, &u.FCMToken, &u.Enabled, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: username %q already exists", ErrConflict, username)
			}
			return fmt.Errorf("insert root user: %w", err)
		}

		// The bootstrapped root is the protected site-admin. is_root confers no
		// permissions on its own (they derive from roles), so grant the site-admin
		// role too, or the first /setup user is locked out of the admin console.
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '')
			 ON CONFLICT DO NOTHING`, u.ID); err != nil {
			return fmt.Errorf("grant root site-admin: %w", err)
		}

		if err := s.emitAuditTx(ctx, tx, "user.bootstrap_root", nil, "bootstrap", &u.ID, nil,
			map[string]any{"email": email, "username": username, "local": true, "is_root": true}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return User{}, err
	}
	return s.GetUser(ctx, u.ID)
}

// isUniqueViolation checks whether err is a Postgres unique-constraint error.
// It delegates to mapPgError so the matching logic is consistent with the rest
// of the store layer (containsSubstr on "unique constraint" / "duplicate key"
// / SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return containsSubstr(msg, "23505") ||
		containsSubstr(msg, "unique constraint") ||
		containsSubstr(msg, "duplicate key")
}
