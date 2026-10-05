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

// GetGroup loads a group by id.
func (s *Store) GetGroup(ctx context.Context, id uuid.UUID) (Group, error) {
	var g Group
	var parent *uuid.UUID
	var rawMeta []byte
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, parent_id, metadata, created_at, updated_at
		 FROM groups WHERE id = $1`, id,
	).Scan(&g.ID, &g.Name, &parent, &rawMeta, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Group{}, ErrNotFound
		}
		return Group{}, fmt.Errorf("get group: %w", err)
	}
	if parent != nil {
		g.ParentID = *parent
	}
	if err := unmarshalMetadata(rawMeta, &g.Metadata); err != nil {
		return Group{}, err
	}
	return g, nil
}

func unmarshalMetadata(raw []byte, out *map[string]string) error {
	if len(raw) == 0 {
		*out = map[string]string{}
		return nil
	}
	m := map[string]string{}
	// jsonb returns a JSON object; values can be arbitrary, but per spec our
	// metadata is string keyed and string valued for V1.
	if err := json.Unmarshal(raw, &m); err != nil {
		// Non-string values in metadata are not expected; fall back to empty
		// rather than fail the whole load.
		*out = map[string]string{}
		return nil
	}
	*out = m
	return nil
}

// CreateGroup inserts a new group. parent==uuid.Nil → root group.
func (s *Store) CreateGroup(ctx context.Context, name string, parent uuid.UUID,
	metadata map[string]string, actor *uuid.UUID, actorExternal string) (Group, error) {
	if name == "" {
		return Group{}, fmt.Errorf("%w: name required", ErrInvalid)
	}
	var parentArg any
	var g Group
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var err error
		if parent != uuid.Nil {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1)`, parent).Scan(&ok); err != nil {
				return fmt.Errorf("parent exists check: %w", err)
			}
			if !ok {
				return fmt.Errorf("%w: parent_id", ErrNotFound)
			}
		}

		rawMeta, err := json.Marshal(metadata)
		if err != nil {
			return fmt.Errorf("marshal metadata: %w", err)
		}
		if parent != uuid.Nil {
			parentArg = parent
		}
		g = Group{Name: name, ParentID: parent, Metadata: metadata}
		if g.Metadata == nil {
			g.Metadata = map[string]string{}
		}
		err = tx.QueryRow(ctx,
			`INSERT INTO groups (name, parent_id, metadata) VALUES ($1, $2, $3::jsonb)
			 RETURNING id, created_at, updated_at`,
			name, parentArg, rawMeta,
		).Scan(&g.ID, &g.CreatedAt, &g.UpdatedAt)
		if err != nil {
			return mapPgError(err, ErrConflict)
		}

		if err := s.emitAuditTx(ctx, tx, "group.created", actor, actorExternal, nil, &g.ID, map[string]any{"name": name}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return Group{}, err
	}
	return g, nil
}

// RenameGroup updates groups.name. Returns the updated group.
func (s *Store) RenameGroup(ctx context.Context, id uuid.UUID, newName string,
	actor *uuid.UUID, actorExternal string) (Group, error) {
	if newName == "" {
		return Group{}, fmt.Errorf("%w: new_name required", ErrInvalid)
	}
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE groups SET name = $2, updated_at = now() WHERE id = $1`, id, newName)
		if err != nil {
			return mapPgError(err, ErrConflict)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "group.renamed", actor, actorExternal, nil, &id, map[string]any{"new_name": newName}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return Group{}, err
	}
	return s.GetGroup(ctx, id)
}

// DeleteGroup removes a group. Refuses if it has descendants or members.
func (s *Store) DeleteGroup(ctx context.Context, id uuid.UUID,
	actor *uuid.UUID, actorExternal string) error {
	return s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var hasChildren bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM groups WHERE parent_id = $1)`, id).Scan(&hasChildren); err != nil {
			return fmt.Errorf("children check: %w", err)
		}
		if hasChildren {
			return ErrHasChildren
		}

		var hasMembers bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM group_membership WHERE group_id = $1)`, id).Scan(&hasMembers); err != nil {
			return fmt.Errorf("members check: %w", err)
		}
		if hasMembers {
			return ErrHasMembers
		}

		// Emit the audit row BEFORE the delete so the FK on target_group_id is
		// satisfied. Both rows commit together (or both rollback) so the audit
		// trail still mirrors the action atomically.
		if err := s.emitAuditTx(ctx, tx, "group.deleted", actor, actorExternal, nil, &id, map[string]any{}); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("delete group: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SetGroupParent re-parents a group. Passing uuid.Nil moves to root.
// Cycles are caught by the trigger; we surface them as ErrCycle.
func (s *Store) SetGroupParent(ctx context.Context, id uuid.UUID, newParent uuid.UUID,
	actor *uuid.UUID, actorExternal string) (Group, error) {
	if id == newParent && id != uuid.Nil {
		return Group{}, ErrCycle
	}
	var parentArg any
	if err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if newParent != uuid.Nil {
			parentArg = newParent
			// Validate new parent exists; the trigger only catches cycles.
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1)`, newParent).Scan(&ok); err != nil {
				return fmt.Errorf("parent exists check: %w", err)
			}
			if !ok {
				return fmt.Errorf("%w: new_parent_id", ErrNotFound)
			}
		}

		tag, err := tx.Exec(ctx,
			`UPDATE groups SET parent_id = $2, updated_at = now() WHERE id = $1`,
			id, parentArg)
		if err != nil {
			// Trigger raises generic exception; map by message substring.
			if isCycleErr(err) {
				return ErrCycle
			}
			return mapPgError(err, ErrConflict)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		if err := s.emitAuditTx(ctx, tx, "group.reparented", actor, actorExternal, nil, &id, map[string]any{"new_parent_id": newParent.String()}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return Group{}, err
	}
	return s.GetGroup(ctx, id)
}

// ListGroups returns groups under parent (uuid.Nil = root-level only). When
// includeDescendants is true, the result is the transitive closure rooted at
// parent (or every group, if parent==uuid.Nil). Result is sorted by name
// ASC, then id ASC for stability across cursor pages.
//
// Pagination uses a (name, id) tuple cursor so name-collisions don't cause
// rows to be skipped. limit==0 falls back to 50; the handler clamps any
// caller-supplied limit to 200.
//
// The store does NOT enforce a 200-row cap; that is the handler's job (kept
// here so unit tests can drive larger windows without re-mocking).
func (s *Store) ListGroups(ctx context.Context, parent uuid.UUID, includeDescendants bool, limit int, cursorName string, cursorID uuid.UUID) ([]Group, error) {
	if limit <= 0 {
		limit = 50
	}

	// Four shapes, depending on (parent set?, descendants?). All variants
	// emit the same column list + ORDER BY so scanGroups can be reused.
	const cols = "id, name, parent_id, metadata, created_at, updated_at"
	var rows pgx.Rows
	var err error
	switch {
	case parent == uuid.Nil && !includeDescendants:
		// Direct root-level groups.
		rows, err = s.pool.Query(ctx, `
			SELECT `+cols+`
			  FROM groups
			 WHERE parent_id IS NULL
			   AND ($1 = '' OR (name, id) > ($1, $2))
			 ORDER BY name ASC, id ASC
			 LIMIT $3`,
			cursorName, cursorID, limit)
	case parent == uuid.Nil && includeDescendants:
		// Whole tree.
		rows, err = s.pool.Query(ctx, `
			SELECT `+cols+`
			  FROM groups
			 WHERE ($1 = '' OR (name, id) > ($1, $2))
			 ORDER BY name ASC, id ASC
			 LIMIT $3`,
			cursorName, cursorID, limit)
	case parent != uuid.Nil && !includeDescendants:
		// Direct children of parent.
		rows, err = s.pool.Query(ctx, `
			SELECT `+cols+`
			  FROM groups
			 WHERE parent_id = $1
			   AND ($2 = '' OR (name, id) > ($2, $3))
			 ORDER BY name ASC, id ASC
			 LIMIT $4`,
			parent, cursorName, cursorID, limit)
	default:
		// All descendants of parent (excluding parent itself).
		rows, err = s.pool.Query(ctx, `
			WITH RECURSIVE descendants AS (
			  SELECT id, name, parent_id, metadata, created_at, updated_at
			    FROM groups WHERE parent_id = $1
			  UNION ALL
			  SELECT g.id, g.name, g.parent_id, g.metadata, g.created_at, g.updated_at
			    FROM groups g JOIN descendants d ON g.parent_id = d.id
			)
			SELECT `+cols+`
			  FROM descendants
			 WHERE ($2 = '' OR (name, id) > ($2, $3))
			 ORDER BY name ASC, id ASC
			 LIMIT $4`,
			parent, cursorName, cursorID, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()
	return scanGroups(rows)
}

// ListDescendants returns every descendant group of root (excluding root
// itself), depth-first by row order so callers can walk the chain.
func (s *Store) ListDescendants(ctx context.Context, root uuid.UUID) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE descendants AS (
		  SELECT id, name, parent_id, metadata, created_at, updated_at, 0 AS depth
		  FROM groups WHERE parent_id = $1
		  UNION ALL
		  SELECT g.id, g.name, g.parent_id, g.metadata, g.created_at, g.updated_at, d.depth + 1
		  FROM groups g JOIN descendants d ON g.parent_id = d.id
		)
		SELECT id, name, parent_id, metadata, created_at, updated_at
		FROM descendants ORDER BY depth ASC, name ASC`, root)
	if err != nil {
		return nil, fmt.Errorf("list descendants: %w", err)
	}
	defer rows.Close()
	return scanGroups(rows)
}

// ListAncestors returns the ancestor chain of id, leaf-first (index 0 is id's
// parent, last is the root).
func (s *Store) ListAncestors(ctx context.Context, id uuid.UUID) ([]Group, error) {
	rows, err := s.pool.Query(ctx, `
		WITH RECURSIVE chain AS (
		  SELECT id, name, parent_id, metadata, created_at, updated_at, 0 AS depth
		  FROM groups WHERE id = (SELECT parent_id FROM groups WHERE id = $1)
		  UNION ALL
		  SELECT g.id, g.name, g.parent_id, g.metadata, g.created_at, g.updated_at, c.depth + 1
		  FROM groups g JOIN chain c ON g.id = c.parent_id
		)
		SELECT id, name, parent_id, metadata, created_at, updated_at
		FROM chain ORDER BY depth ASC`, id)
	if err != nil {
		return nil, fmt.Errorf("list ancestors: %w", err)
	}
	defer rows.Close()
	return scanGroups(rows)
}

func scanGroups(rows pgx.Rows) ([]Group, error) {
	var out []Group
	for rows.Next() {
		var g Group
		var parent *uuid.UUID
		var rawMeta []byte
		if err := rows.Scan(&g.ID, &g.Name, &parent, &rawMeta, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		if parent != nil {
			g.ParentID = *parent
		}
		_ = unmarshalMetadata(rawMeta, &g.Metadata)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// isCycleErr matches the message emitted by the groups_no_cycle trigger.
func isCycleErr(err error) bool {
	return err != nil && containsSubstr(err.Error(), "group cycle")
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// mapPgError converts a pgx-level error to a store-level sentinel where the
// mapping is obvious; otherwise it wraps the original error verbatim.
func mapPgError(err error, fallback error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if containsSubstr(msg, "unique constraint") || containsSubstr(msg, "duplicate key") {
		// Return the bare sentinel: the raw pg error text (constraint names,
		// column values) must not reach the client via statusFromStoreErr,
		// which renders sentinels under client-facing codes (AlreadyExists).
		return fallback
	}
	if containsSubstr(msg, "group cycle") {
		return ErrCycle
	}
	return err
}
