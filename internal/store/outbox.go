// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Steward-GRC/steward-identity/internal/audit"
)

// AuditTable is the go-outbox table audit events wait in until the relay
// publishes them.
const AuditTable = "audit_outbox"

// AuditEvent is one audit event as the store records it.
type AuditEvent = audit.Event

// EmitAudit records e in a transaction of its own.
func (s *Store) EmitAudit(ctx context.Context, e AuditEvent) error {
	return s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		return s.enqueueAudit(ctx, tx, e)
	})
}

func (s *Store) enqueueAudit(ctx context.Context, tx pgx.Tx, e AuditEvent) error {
	msg, err := audit.Encode(ctx, e)
	if err != nil {
		return err
	}
	if _, err := s.ob.Enqueue(ctx, tx, msg); err != nil {
		return fmt.Errorf("enqueue audit: %w", err)
	}
	return nil
}

// emitAuditTx records an audit event inside tx, so the event exists only if
// the change it records commits.
func (s *Store) emitAuditTx(ctx context.Context, tx pgx.Tx, eventType string,
	actor *uuid.UUID, actorExternal string,
	targetUser *uuid.UUID, targetGroup *uuid.UUID, payload map[string]any) error {
	return s.enqueueAudit(ctx, tx, AuditEvent{
		EventType: eventType, ActorUserID: actor, ActorExternal: actorExternal,
		TargetUserID: targetUser, TargetGroupID: targetGroup, Payload: payload,
	})
}

// PendingAuditEvents reads up to limit events the relay hasn't published
// yet, oldest first.
func (s *Store) PendingAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, payload FROM `+s.ob.Table()+` WHERE status = 'pending' ORDER BY id ASC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("query pending audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var id int64
		var body []byte
		if err := rows.Scan(&id, &body); err != nil {
			return nil, err
		}
		e, err := audit.Decode(body)
		if err != nil {
			return nil, err
		}
		e.ID = id
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountAuditPending counts the events the relay hasn't published yet.
func (s *Store) CountAuditPending(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM `+s.ob.Table()+` WHERE status = 'pending'`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
