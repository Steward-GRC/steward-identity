// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IdPGroupMapping maps a single asserted IdP group-claim value to a
// platform group by id. The target is a group UUID (not a name): group
// names are unique only per-parent, so a name-based mapping could silently
// resolve to the WRONG same-named group during JIT provisioning. Applying a
// mapping never fails when the target group no longer exists —
// ApplyIdPGroupMappings just reports it back as skipped so a stale mapping
// can't break a login.
type IdPGroupMapping struct {
	ID                 uuid.UUID
	ConnectionID       uuid.UUID
	IdPGroupClaimValue string
	TargetGroupID      uuid.UUID
}

// AddIdPGroupMapping registers a single idp-group-value -> target-group-id
// mapping for a connection. The migration's FK (target_group_id REFERENCES
// groups(id) ON DELETE CASCADE) enforces that the target group exists at
// creation time and that the mapping is removed if the group is later deleted.
func (s *Store) AddIdPGroupMapping(ctx context.Context, connID uuid.UUID, idpValue string, targetGroupID uuid.UUID) (IdPGroupMapping, error) {
	m := IdPGroupMapping{
		ConnectionID:       connID,
		IdPGroupClaimValue: idpValue,
		TargetGroupID:      targetGroupID,
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO idp_group_mappings (connection_id, idp_group_claim_value, target_group_id)
		 VALUES ($1, $2, $3)
		 RETURNING id`,
		connID, idpValue, targetGroupID).
		Scan(&m.ID)
	if err != nil {
		return IdPGroupMapping{}, mapPgError(err, ErrConflict)
	}
	return m, nil
}

// ListIdPGroupMappings returns every group mapping configured for a
// connection, ordered by idp group-claim value for stable listing.
func (s *Store) ListIdPGroupMappings(ctx context.Context, connID uuid.UUID) ([]IdPGroupMapping, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, connection_id, idp_group_claim_value, target_group_id
		 FROM idp_group_mappings WHERE connection_id = $1
		 ORDER BY idp_group_claim_value`, connID)
	if err != nil {
		return nil, fmt.Errorf("list idp group mappings: %w", err)
	}
	defer rows.Close()
	out := []IdPGroupMapping{}
	for rows.Next() {
		var m IdPGroupMapping
		if err := rows.Scan(&m.ID, &m.ConnectionID, &m.IdPGroupClaimValue, &m.TargetGroupID); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteIdPGroupMapping removes a single mapping by id.
func (s *Store) DeleteIdPGroupMapping(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM idp_group_mappings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// idpJITActor is the audit actor_external recorded for group memberships
// applied via SSO group-mapping JIT sync (no platform-user actor exists for
// this path).
const idpJITActor = "sso-jit"

// ApplyIdPGroupMappings reconciles a freshly-authenticated SSO user's
// asserted IdP groups against the connection's configured mappings. For
// each asserted group that has a mapping whose target group still exists
// (resolved DIRECTLY by target_group_id — no ambiguous name lookup), the
// user is added to that group (AddUserToGroup, actor "sso-jit"). A mapping
// whose target group id no longer exists is reported in skipped rather than
// failing the whole login — a stale mapping must never lock a user out
// (the migration's ON DELETE CASCADE normally removes such mappings, so
// skipped is a defensive guard). An asserted group with no mapping at all
// is silently ignored (neither applied nor skipped). applied/skipped carry
// the platform group ids; callers that need display names resolve them.
func (s *Store) ApplyIdPGroupMappings(ctx context.Context, userID, connID uuid.UUID, idpGroups []string) (applied []uuid.UUID, skipped []uuid.UUID, err error) {
	mappings, err := s.ListIdPGroupMappings(ctx, connID)
	if err != nil {
		return nil, nil, fmt.Errorf("load idp group mappings: %w", err)
	}
	byValue := make(map[string]uuid.UUID, len(mappings))
	for _, m := range mappings {
		byValue[m.IdPGroupClaimValue] = m.TargetGroupID
	}

	applied = []uuid.UUID{}
	skipped = []uuid.UUID{}
	for _, idpGroup := range idpGroups {
		targetID, ok := byValue[idpGroup]
		if !ok {
			// No mapping at all for this asserted group: ignore.
			continue
		}
		// Resolve membership directly by id. If the target group no longer
		// exists, skip it (never fail the login).
		if _, gerr := s.GetGroup(ctx, targetID); errors.Is(gerr, ErrNotFound) {
			skipped = append(skipped, targetID)
			continue
		} else if gerr != nil {
			return nil, nil, fmt.Errorf("resolve target group %q: %w", targetID, gerr)
		}
		if _, err := s.AddUserToGroup(ctx, userID, targetID, nil, idpJITActor, SourceIdPSync); err != nil {
			return nil, nil, fmt.Errorf("add user to group %q: %w", targetID, err)
		}
		applied = append(applied, targetID)
	}
	return applied, skipped, nil
}

// GetIdPConnection looks up a customer IdP connection by id. This is the
// lookup ActivateOrganization uses to check the test-passed gate before
// enabling a connection. ErrNotFound when no connection has that id.
func (s *Store) GetIdPConnection(ctx context.Context, id uuid.UUID) (IdPConnection, error) {
	var c IdPConnection
	var rawConfig []byte
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_name, protocol, connection_alias, display_name, config, secret_ref, enabled, jit_enabled, allow_local, test_passed_at, created_at, updated_at
		 FROM idp_connections WHERE id = $1`, id).
		Scan(&c.ID, &c.OrgName, &c.Protocol, &c.ConnectionAlias, &c.DisplayName, &rawConfig, &c.SecretRef, &c.Enabled, &c.JitEnabled, &c.AllowLocal, &c.TestPassedAt, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdPConnection{}, ErrNotFound
	}
	if err != nil {
		return IdPConnection{}, fmt.Errorf("get idp connection: %w", err)
	}
	if len(rawConfig) > 0 {
		if err := json.Unmarshal(rawConfig, &c.Config); err != nil {
			return IdPConnection{}, fmt.Errorf("unmarshal config: %w", err)
		}
	}
	return c, nil
}

// GetIdPConnectionByAlias looks up an IdP connection by its connection
// alias. This is the lookup ResolveClaims uses to resolve the connection a
// sign-in names, before applying its
// group mappings. ErrNotFound when no connection has that alias.
func (s *Store) GetIdPConnectionByAlias(ctx context.Context, alias string) (IdPConnection, error) {
	var c IdPConnection
	var rawConfig []byte
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_name, protocol, connection_alias, display_name, config, secret_ref, enabled, jit_enabled, allow_local, test_passed_at, created_at, updated_at
		 FROM idp_connections WHERE connection_alias = $1`, alias).
		Scan(&c.ID, &c.OrgName, &c.Protocol, &c.ConnectionAlias, &c.DisplayName, &rawConfig, &c.SecretRef, &c.Enabled, &c.JitEnabled, &c.AllowLocal, &c.TestPassedAt, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdPConnection{}, ErrNotFound
	}
	if err != nil {
		return IdPConnection{}, fmt.Errorf("get idp connection by alias: %w", err)
	}
	if len(rawConfig) > 0 {
		if err := json.Unmarshal(rawConfig, &c.Config); err != nil {
			return IdPConnection{}, fmt.Errorf("unmarshal config: %w", err)
		}
	}
	return c, nil
}
