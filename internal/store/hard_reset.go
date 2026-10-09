// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The states of a hard reset request.
const (
	HardResetPending   = "pending"
	HardResetApproved  = "approved"
	HardResetCancelled = "cancelled"
	HardResetConsumed  = "consumed"
	HardResetExpired   = "expired"
)

// HardResetRequest is one two-person hard reset of a module.
type HardResetRequest struct {
	ID                uuid.UUID
	Module            string
	Reason            string
	State             string
	RequestedBy       uuid.UUID
	RequestedAt       time.Time
	ExpiresAt         time.Time
	ApprovedBy        *uuid.UUID
	ApprovedAt        *time.Time
	ApprovalExpiresAt *time.Time
	CancelledAt       *time.Time
	ConsumedAt        *time.Time
	ConsumedBy        string
}

const hardResetColumns = `id, module, reason, state, requested_by, requested_at, expires_at,
	approved_by, approved_at, approval_expires_at, cancelled_at, consumed_at, consumed_by`

func scanHardReset(row pgx.Row) (HardResetRequest, error) {
	var r HardResetRequest
	err := row.Scan(&r.ID, &r.Module, &r.Reason, &r.State, &r.RequestedBy, &r.RequestedAt, &r.ExpiresAt,
		&r.ApprovedBy, &r.ApprovedAt, &r.ApprovalExpiresAt, &r.CancelledAt, &r.ConsumedAt, &r.ConsumedBy)
	return r, err
}

func hardResetPayload(r HardResetRequest) map[string]any {
	return map[string]any{"request_id": r.ID.String(), "module": r.Module}
}

// expireHardResets marks every open request past its deadline expired and
// records each one. It runs first in every hard reset transaction, so the
// state a step checks is current.
func (s *Store) expireHardResets(ctx context.Context, tx pgx.Tx, now time.Time) error {
	rows, err := tx.Query(ctx,
		`UPDATE hard_reset_requests SET state = 'expired'
		  WHERE (state = 'pending' AND expires_at <= $1)
		     OR (state = 'approved' AND approval_expires_at <= $1)
		 RETURNING `+hardResetColumns, now)
	if err != nil {
		return fmt.Errorf("expire hard resets: %w", err)
	}
	var expired []HardResetRequest
	for rows.Next() {
		r, err := scanHardReset(rows)
		if err != nil {
			rows.Close()
			return fmt.Errorf("scan expired hard reset: %w", err)
		}
		expired = append(expired, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("expire hard resets: %w", err)
	}
	for _, r := range expired {
		if err := s.emitAuditTx(ctx, tx, "hard_reset.expired", nil, "system", nil, nil, hardResetPayload(r)); err != nil {
			return err
		}
	}
	return nil
}

func requireRootTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	var root bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND is_root AND enabled AND deleted_at IS NULL)`,
		userID).Scan(&root); err != nil {
		return fmt.Errorf("root check: %w", err)
	}
	if !root {
		return ErrRootRequired
	}
	return nil
}

func lockHardReset(ctx context.Context, tx pgx.Tx, id uuid.UUID) (HardResetRequest, error) {
	r, err := scanHardReset(tx.QueryRow(ctx,
		`SELECT `+hardResetColumns+` FROM hard_reset_requests WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return HardResetRequest{}, ErrNotFound
	}
	if err != nil {
		return HardResetRequest{}, fmt.Errorf("load hard reset: %w", err)
	}
	return r, nil
}

// CreateHardResetRequest records a root admin's request to hard reset module.
// It must be approved within ttl. A module with an open request refuses a
// second one (ErrConflict).
func (s *Store) CreateHardResetRequest(ctx context.Context, module, reason string, requester uuid.UUID, now time.Time, ttl time.Duration) (HardResetRequest, error) {
	var out HardResetRequest
	err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := s.expireHardResets(ctx, tx, now); err != nil {
			return err
		}
		if err := requireRootTx(ctx, tx, requester); err != nil {
			return err
		}
		r, err := scanHardReset(tx.QueryRow(ctx,
			`INSERT INTO hard_reset_requests (module, reason, requested_by, requested_at, expires_at)
			 VALUES ($1, $2, $3, $4, $5)
			 RETURNING `+hardResetColumns,
			module, reason, requester, now, now.Add(ttl)))
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("%w: module %q already has an open hard reset request", ErrConflict, module)
			}
			return fmt.Errorf("insert hard reset: %w", err)
		}
		p := hardResetPayload(r)
		p["reason"] = reason
		p["expires_at"] = r.ExpiresAt.UTC().Format(time.RFC3339)
		if err := s.emitAuditTx(ctx, tx, "hard_reset.requested", &requester, "", nil, nil, p); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ApproveHardResetRequest records a second root admin's approval. The
// requester can't approve (ErrSelfApproval); the request must still be
// pending (ErrHardResetState). The approval can be redeemed once within ttl.
func (s *Store) ApproveHardResetRequest(ctx context.Context, id, approver uuid.UUID, now time.Time, ttl time.Duration) (HardResetRequest, error) {
	var out HardResetRequest
	err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := s.expireHardResets(ctx, tx, now); err != nil {
			return err
		}
		r, err := lockHardReset(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := requireRootTx(ctx, tx, approver); err != nil {
			return err
		}
		if r.RequestedBy == approver {
			return ErrSelfApproval
		}
		if r.State != HardResetPending {
			return fmt.Errorf("%w: it is %s", ErrHardResetState, r.State)
		}
		r, err = scanHardReset(tx.QueryRow(ctx,
			`UPDATE hard_reset_requests
			    SET state = 'approved', approved_by = $2, approved_at = $3, approval_expires_at = $4
			  WHERE id = $1
			 RETURNING `+hardResetColumns, id, approver, now, now.Add(ttl)))
		if err != nil {
			return fmt.Errorf("approve hard reset: %w", err)
		}
		p := hardResetPayload(r)
		p["requested_by"] = r.RequestedBy.String()
		p["approval_expires_at"] = r.ApprovalExpiresAt.UTC().Format(time.RFC3339)
		if err := s.emitAuditTx(ctx, tx, "hard_reset.approved", &approver, "", nil, nil, p); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// CancelHardResetRequest withdraws a pending or approved request. Only its
// requester may (ErrNotRequester).
func (s *Store) CancelHardResetRequest(ctx context.Context, id, requester uuid.UUID, now time.Time) (HardResetRequest, error) {
	var out HardResetRequest
	err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := s.expireHardResets(ctx, tx, now); err != nil {
			return err
		}
		r, err := lockHardReset(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.RequestedBy != requester {
			return ErrNotRequester
		}
		if r.State != HardResetPending && r.State != HardResetApproved {
			return fmt.Errorf("%w: it is %s", ErrHardResetState, r.State)
		}
		r, err = scanHardReset(tx.QueryRow(ctx,
			`UPDATE hard_reset_requests SET state = 'cancelled', cancelled_at = $2 WHERE id = $1
			 RETURNING `+hardResetColumns, id, now))
		if err != nil {
			return fmt.Errorf("cancel hard reset: %w", err)
		}
		if err := s.emitAuditTx(ctx, tx, "hard_reset.cancelled", &requester, "", nil, nil, hardResetPayload(r)); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ConsumeHardResetRequest redeems an approved, unexpired request for module
// once, on behalf of the service that runs the reset.
func (s *Store) ConsumeHardResetRequest(ctx context.Context, id uuid.UUID, module, consumer string, now time.Time) (HardResetRequest, error) {
	var out HardResetRequest
	err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := s.expireHardResets(ctx, tx, now); err != nil {
			return err
		}
		r, err := lockHardReset(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.State != HardResetApproved {
			return fmt.Errorf("%w: it is %s", ErrHardResetState, r.State)
		}
		if r.Module != module {
			return fmt.Errorf("%w: it is for another module", ErrHardResetState)
		}
		r, err = scanHardReset(tx.QueryRow(ctx,
			`UPDATE hard_reset_requests SET state = 'consumed', consumed_at = $2, consumed_by = $3 WHERE id = $1
			 RETURNING `+hardResetColumns, id, now, consumer))
		if err != nil {
			return fmt.Errorf("consume hard reset: %w", err)
		}
		p := hardResetPayload(r)
		p["requested_by"] = r.RequestedBy.String()
		p["approved_by"] = r.ApprovedBy.String()
		if err := s.emitAuditTx(ctx, tx, "hard_reset.consumed", nil, "service:"+consumer, nil, nil, p); err != nil {
			return err
		}
		out = r
		return nil
	})
	return out, err
}

// ListHardResetRequests lists the requests, newest first, optionally for one
// module, after marking the overdue ones expired.
func (s *Store) ListHardResetRequests(ctx context.Context, module string, now time.Time) ([]HardResetRequest, error) {
	var out []HardResetRequest
	err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		if err := s.expireHardResets(ctx, tx, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT `+hardResetColumns+` FROM hard_reset_requests
			  WHERE $1 = '' OR module = $1
			  ORDER BY requested_at DESC`, module)
		if err != nil {
			return fmt.Errorf("list hard resets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanHardReset(rows)
			if err != nil {
				return fmt.Errorf("scan hard reset: %w", err)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
