// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Account merge persistence: the operation's idempotency record, the per-step
// rows that make a partial failure resumable, the preference move and the
// final tombstone of the source. The cross-service steps (core reassign,
// acknowledgement transfer, workflow reassign) run in the merge saga; each
// step here is atomic and idempotent.

// Merge step names — the stable identifiers persisted in merge_operation_steps
// and surfaced on the RPC response.
const (
	MergeStepCoreReassign     = "core_reassign"
	MergeStepAckTransfer      = "ack_transfer"
	MergeStepWorkflowReassign = "workflow_reassign" // #nosec G101 -- a step name
	MergeStepIdentityPrefs    = "identity_prefs"
	MergeStepSessionRevoke    = "session_revoke"
	MergeStepAuditEvent       = "audit_event"
	MergeStepTombstoneSource  = "tombstone_source"
)

// Merge step statuses.
const (
	MergeStepPending   = "pending"
	MergeStepCompleted = "completed"
	MergeStepFailed    = "failed"
	MergeStepSkipped   = "skipped"
)

// Merge operation statuses.
const (
	MergeOpInProgress = "in_progress"
	MergeOpPartial    = "partial"
	MergeOpCompleted  = "completed"
	MergeOpFailed     = "failed"
)

// MergeParties is the resolved, guard-checked pair for a merge.
type MergeParties struct {
	Source User
	Target User
	// SourceIsRoot / SourceIsSiteAdmin drive the privileged-confirm gate: merging
	// away a root or site-admin account requires an explicit extra confirmation.
	SourceIsRoot      bool
	SourceIsSiteAdmin bool
}

// MergeOperation is one merge invocation's durable record.
type MergeOperation struct {
	ID            uuid.UUID
	Status        string
	Counts        map[string]any
	stepsExisting map[string]string // step -> status, loaded on Begin for resume
}

// StepStatus returns the persisted status of a step ("" if the step has no row
// yet), used by the orchestrator to skip already-completed steps on a re-run.
func (o MergeOperation) StepStatus(step string) string { return o.stepsExisting[step] }

// MergePreflight loads both accounts, enforces the structural guards (both
// exist; source != target), and reports the privileged flags + target enabled
// state the orchestrator needs. It never mutates.
func (s *Store) MergePreflight(ctx context.Context, sourceID, targetID uuid.UUID) (MergeParties, error) {
	if sourceID == targetID {
		return MergeParties{}, fmt.Errorf("%w: source and target are the same account", ErrInvalid)
	}
	src, err := s.GetUser(ctx, sourceID)
	if err != nil {
		return MergeParties{}, fmt.Errorf("load source: %w", err)
	}
	tgt, err := s.GetUser(ctx, targetID)
	if err != nil {
		return MergeParties{}, fmt.Errorf("load target: %w", err)
	}
	p := MergeParties{Source: src, Target: tgt, SourceIsRoot: src.IsRoot}
	if slices.Contains(src.Roles, "site-admin") {
		p.SourceIsSiteAdmin = true
	}
	return p, nil
}

// BeginMergeOperation idempotently creates (or re-attaches to) the merge
// operation for idempotencyKey. On a first call it inserts an in_progress row;
// on a re-run with the same key it returns the existing row and its per-step
// statuses so the orchestrator can RESUME (skipping completed steps) rather than
// re-doing or duplicating work.
func (s *Store) BeginMergeOperation(ctx context.Context, idempotencyKey string, sourceID, targetID uuid.UUID, actor *uuid.UUID, actorExternal string) (MergeOperation, error) {
	var (
		id        uuid.UUID
		status    string
		countsRaw []byte
	)
	err := s.pool.QueryRow(ctx,
		`INSERT INTO merge_operations (idempotency_key, source_user_id, target_user_id, actor_user_id, actor_external)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (idempotency_key)
		   DO UPDATE SET updated_at = now()
		 RETURNING id, status, counts`,
		idempotencyKey, sourceID, targetID, nullableUUID(actor), actorExternal).
		Scan(&id, &status, &countsRaw)
	if err != nil {
		return MergeOperation{}, fmt.Errorf("begin merge operation: %w", err)
	}
	op := MergeOperation{ID: id, Status: status, Counts: map[string]any{}, stepsExisting: map[string]string{}}
	if len(countsRaw) > 0 {
		_ = json.Unmarshal(countsRaw, &op.Counts)
	}
	rows, err := s.pool.Query(ctx, `SELECT step, status FROM merge_operation_steps WHERE merge_operation_id = $1`, id)
	if err != nil {
		return MergeOperation{}, fmt.Errorf("load merge steps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var step, st string
		if err := rows.Scan(&step, &st); err != nil {
			return MergeOperation{}, err
		}
		op.stepsExisting[step] = st
	}
	return op, rows.Err()
}

// SetMergeStep upserts a step row. detail carries a human summary; errStr is
// non-empty only for a failed step.
func (s *Store) SetMergeStep(ctx context.Context, opID uuid.UUID, step, status, detail, errStr string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO merge_operation_steps (merge_operation_id, step, status, detail, error, updated_at)
		 VALUES ($1, $2, $3, $4, $5, now())
		 ON CONFLICT (merge_operation_id, step)
		   DO UPDATE SET status = EXCLUDED.status, detail = EXCLUDED.detail, error = EXCLUDED.error, updated_at = now()`,
		opID, step, status, detail, errStr)
	if err != nil {
		return fmt.Errorf("set merge step %s: %w", step, err)
	}
	return nil
}

// SetMergeCounts persists the running per-record-type tallies so a resume
// recovers the counts of already-completed steps.
func (s *Store) SetMergeCounts(ctx context.Context, opID uuid.UUID, counts map[string]any) error {
	raw, err := json.Marshal(counts)
	if err != nil {
		return fmt.Errorf("marshal counts: %w", err)
	}
	_, err = s.pool.Exec(ctx, `UPDATE merge_operations SET counts = $2::jsonb, updated_at = now() WHERE id = $1`, opID, raw)
	if err != nil {
		return fmt.Errorf("set merge counts: %w", err)
	}
	return nil
}

// SetMergeStatus updates the operation-level status.
func (s *Store) SetMergeStatus(ctx context.Context, opID uuid.UUID, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE merge_operations SET status = $2, updated_at = now() WHERE id = $1`, opID, status)
	if err != nil {
		return fmt.Errorf("set merge status: %w", err)
	}
	return nil
}

// MovePreferences copies the source's user preferences (timezone, locale) onto
// the target ONLY where the target has none set, so an existing target
// preference is never clobbered. Returns the number of preference fields moved.
// Idempotent: a re-run finds the target already populated and moves nothing.
func (s *Store) MovePreferences(ctx context.Context, sourceID, targetID uuid.UUID) (int, error) {
	var src, tgt User
	var err error
	if src, err = s.GetUser(ctx, sourceID); err != nil {
		return 0, fmt.Errorf("load source: %w", err)
	}
	if tgt, err = s.GetUser(ctx, targetID); err != nil {
		return 0, fmt.Errorf("load target: %w", err)
	}
	moved := 0
	newTZ, newLocale := tgt.Timezone, tgt.Locale
	if tgt.Timezone == "" && src.Timezone != "" {
		newTZ = src.Timezone
		moved++
	}
	if tgt.Locale == "" && src.Locale != "" {
		newLocale = src.Locale
		moved++
	}
	if moved == 0 {
		return 0, nil
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE users SET timezone = $2, locale = $3, updated_at = now() WHERE id = $1`,
		targetID, newTZ, newLocale); err != nil {
		return 0, fmt.Errorf("move preferences: %w", err)
	}
	return moved, nil
}

// TombstoneMergedSource is the final merge step. In one transaction it
// stamps the source deleted_at (kept on a repeat), sets merged_into_user_id
// to the target and disables it, drops the source's identity access rows
// (never a policy: those already moved in the core step), records one
// user.accounts_merged audit event (actor: the admin, subject: the target)
// with both ids and the counts, and marks the operation completed. The
// source's sessions are in the sign-in service, so the caller revokes them in
// its own step. The root account can't be merged away.
func (s *Store) TombstoneMergedSource(ctx context.Context, opID, sourceID, targetID uuid.UUID, actor *uuid.UUID, actorExternal string, counts map[string]any) error {
	root, err := s.isRoot(ctx, sourceID)
	if err != nil {
		return err
	}
	if root {
		return fmt.Errorf("%w: cannot merge away the root account", ErrRootProtected)
	}

	return s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var email string
		if err := tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, sourceID).Scan(&email); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("load source: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`UPDATE users
			    SET deleted_at = COALESCE(deleted_at, now()),
			        merged_into_user_id = $2,
			        enabled = false,
			        updated_at = now()
			  WHERE id = $1`,
			sourceID, targetID); err != nil {
			return fmt.Errorf("tombstone source: %w", err)
		}

		for _, table := range []string{
			"group_membership",
			"user_idp_groups",
			"user_roles",
			"user_permissions",
			"user_policy_overrides",
			"break_glass_grants",
		} {
			if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE user_id = $1`, sourceID); err != nil {
				return fmt.Errorf("delete %s: %w", table, err)
			}
		}

		payload := map[string]any{
			"from_user_id":    sourceID.String(),
			"into_user_id":    targetID.String(),
			"source_email":    email,
			"merge_operation": opID.String(),
		}
		maps.Copy(payload, counts)
		if err := s.emitAuditTx(ctx, tx, "user.accounts_merged", actor, actorExternal, &targetID, nil, payload); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `UPDATE merge_operations SET status = $2, updated_at = now() WHERE id = $1`,
			opID, MergeOpCompleted); err != nil {
			return fmt.Errorf("complete merge operation: %w", err)
		}
		return nil
	})
}
