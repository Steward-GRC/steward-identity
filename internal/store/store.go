// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"

	outbox "github.com/Bugs5382/go-outbox"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors returned by the store. Handlers map these to gRPC status codes.
var (
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrInvalid       = errors.New("invalid")
	ErrHasChildren   = errors.New("group has descendants")
	ErrHasMembers    = errors.New("group has members")
	ErrCycle         = errors.New("would create cycle")
	ErrAlreadyAdmin  = errors.New("admin already exists")
	ErrRootProtected = errors.New("root account is protected")
	// ErrEmailMismatch is returned by MarkEmailVerified when the address a
	// verification link was minted for no longer matches the account's current
	// email — a token for a since-changed address must never be honored.
	ErrEmailMismatch = errors.New("email does not match current account address")
	// ErrSyncOwned is returned when a non-site-admin group-manager tries to
	// remove a membership that is owned by the IdP sync (source='idp-sync').
	// Sync-owned memberships are read-only to group-managers; only a site-admin
	// may change them. Handlers map this to PermissionDenied.
	ErrSyncOwned = errors.New("membership is IdP-synced and read-only to group managers")
	// ErrRootRequired: only a root admin may take part in a hard reset.
	ErrRootRequired = errors.New("a root admin is required")
	// ErrSelfApproval: a hard reset's requester can't approve it.
	ErrSelfApproval = errors.New("the requester can't approve their own hard reset")
	// ErrNotRequester: only a hard reset's requester can cancel it.
	ErrNotRequester = errors.New("only the requester can cancel a hard reset")
	// ErrHardResetState: the request is not pending, approved, unexpired or
	// for that module, as the step needs.
	ErrHardResetState = errors.New("the hard reset request doesn't allow this")
)

// Membership provenance values stored in group_membership.source.
const (
	// SourceManual is an admin / self-service / group-manager membership grant.
	SourceManual = "manual"
	// SourceIdPSync is a membership created by the IdP group-mapping path
	// (ApplyIdPGroupMappings, actor "sso-jit").
	SourceIdPSync = "idp-sync"
)

// idpGroupCache is the optional per-user cache of identity provider group
// names the store consults in UserIdpGroups and clears on every change. A nil
// cache reads the database directly.
type idpGroupCache interface {
	GetIdpGroups(ctx context.Context, userID string) ([]string, bool)
	SetIdpGroups(ctx context.Context, userID string, names []string)
	DelIdpGroups(ctx context.Context, userID string)
}

// Store is the entry point the handlers depend on. Every audit event is
// written to the outbox in the same transaction as the change it records.
type Store struct {
	db   *postgres.DB
	pool *pgxpool.Pool
	ob   *outbox.Outbox
	agc  idpGroupCache
}

// New returns a Store on db that writes audit events through ob.
func New(db *postgres.DB, ob *outbox.Outbox) *Store {
	return &Store{db: db, pool: db.Pool(), ob: ob}
}

// WithIdpGroupCache wires the optional identity provider group cache.
func (s *Store) WithIdpGroupCache(c idpGroupCache) *Store { s.agc = c; return s }

// --- helpers ---

func nullableUUID(p *uuid.UUID) any {
	if p == nil {
		return nil
	}
	return *p
}

// loadInto queries rows with a single $1 UUID param and appends UUID values
// into *dest, initialising it to a non-nil empty slice when empty.
func (s *Store) loadInto(ctx context.Context, id uuid.UUID, dest *[]uuid.UUID, sql string) error {
	rows, err := s.pool.Query(ctx, sql, id)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	*dest = []uuid.UUID{}
	for rows.Next() {
		var v uuid.UUID
		if err := rows.Scan(&v); err != nil {
			return err
		}
		*dest = append(*dest, v)
	}
	return rows.Err()
}

// loadStrings queries rows with a single $1 UUID param and appends string
// values into *dest, initialising it to a non-nil empty slice when empty.
func (s *Store) loadStrings(ctx context.Context, id uuid.UUID, dest *[]string, sql string) error {
	rows, err := s.pool.Query(ctx, sql, id)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	*dest = []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return err
		}
		*dest = append(*dest, v)
	}
	return rows.Err()
}

// hydrateUser populates all role/group/idpGroup/exclusion/override collections
// on u. It is the single hydration entry point for every read path.
func (s *Store) hydrateUser(ctx context.Context, u *User) error {
	// roles: split global (scope_category='') from scoped.
	rows, err := s.pool.Query(ctx,
		`SELECT role, scope_category FROM user_roles WHERE user_id=$1 ORDER BY role, scope_category`, u.ID)
	if err != nil {
		return fmt.Errorf("query roles: %w", err)
	}
	u.Roles, u.ScopedRoles = []string{}, []ScopedRole{}
	for rows.Next() {
		var role, cat string
		if err := rows.Scan(&role, &cat); err != nil {
			rows.Close()
			return err
		}
		if cat == "" {
			u.Roles = append(u.Roles, role)
		} else {
			u.ScopedRoles = append(u.ScopedRoles, ScopedRole{Role: role, Category: cat})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if err := s.loadInto(ctx, u.ID, &u.Groups,
		`SELECT group_id FROM group_membership WHERE user_id=$1 ORDER BY group_id`); err != nil {
		return err
	}
	// membership provenance, parallel to Groups: same group ids,
	// each carrying its source so callers can mark idp-sync rows read-only.
	mRows, err := s.pool.Query(ctx,
		`SELECT group_id, source FROM group_membership WHERE user_id=$1 ORDER BY group_id`, u.ID)
	if err != nil {
		return fmt.Errorf("query memberships: %w", err)
	}
	u.Memberships = []Membership{}
	for mRows.Next() {
		var m Membership
		if err := mRows.Scan(&m.GroupID, &m.Source); err != nil {
			mRows.Close()
			return err
		}
		u.Memberships = append(u.Memberships, m)
	}
	mRows.Close()
	if err := mRows.Err(); err != nil {
		return err
	}
	// local group-manager grants: the groups this user may manage
	// the membership of without holding site-admin.
	if err := s.loadInto(ctx, u.ID, &u.ManagedGroups,
		`SELECT group_id FROM group_managers WHERE user_id=$1 ORDER BY group_id`); err != nil {
		return err
	}
	if err := s.loadStrings(ctx, u.ID, &u.IdpGroups,
		`SELECT idp_group_name FROM user_idp_groups WHERE user_id=$1 ORDER BY idp_group_name`); err != nil {
		return err
	}

	ovRows, err := s.pool.Query(ctx,
		`SELECT policy_number, effect FROM user_policy_overrides WHERE user_id=$1 ORDER BY policy_number`, u.ID)
	if err != nil {
		return fmt.Errorf("query overrides: %w", err)
	}
	u.PolicyOverrides = []PolicyOverride{}
	for ovRows.Next() {
		var p PolicyOverride
		if err := ovRows.Scan(&p.PolicyNumber, &p.Effect); err != nil {
			ovRows.Close()
			return err
		}
		u.PolicyOverrides = append(u.PolicyOverrides, p)
	}
	ovRows.Close()
	if err := ovRows.Err(); err != nil {
		return err
	}

	// individual policy.read_sensitive grant (root-only to assign).
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_permissions WHERE user_id=$1 AND permission='policy.read_sensitive')`,
		u.ID).Scan(&u.ReadSensitive); err != nil {
		return fmt.Errorf("query read_sensitive: %w", err)
	}
	return nil
}
