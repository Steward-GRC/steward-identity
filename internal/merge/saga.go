// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"context"
	"errors"
	"fmt"

	"github.com/Bugs5382/go-saga-orchestration/domain"
	"github.com/Bugs5382/go-saga-orchestration/engine/verbs"
	"github.com/Bugs5382/go-saga-orchestration/saga"
	"github.com/Bugs5382/go-saga-orchestration/store/memory"
	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// ErrNotConfigured is returned while a service a merge needs isn't wired.
var ErrNotConfigured = errors.New("merge: a downstream service is not configured")

const workflowID = "identity.account_merge"

// stepOrder is the saga's steps, in order. The tombstone step also writes
// the audit event, so audit_event is reported with it.
var stepOrder = []string{
	store.MergeStepCoreReassign,
	store.MergeStepAckTransfer,
	store.MergeStepWorkflowReassign,
	store.MergeStepIdentityPrefs,
	store.MergeStepSessionRevoke,
	store.MergeStepAuditEvent,
	store.MergeStepTombstoneSource,
}

// mergeRun is one Execute: the saga's verbs write their outcome here and
// into the merge operation's step rows.
type mergeRun struct {
	o             *Orchestrator
	op            store.MergeOperation
	sID, tID      uuid.UUID
	source        string
	target        string
	actorUserID   string
	actorExternal string
	actorPtr      *uuid.UUID
	counts        Counts
	steps         []StepResult
	failed        bool
}

// saga builds an in-process engine for this run. The merge operation's rows
// are the durable record, so the engine's own state can stay in memory.
func (r *mergeRun) saga() (*saga.Saga, error) {
	sg, err := saga.New(saga.Options{Store: memory.New()})
	if err != nil {
		return nil, err
	}
	type step struct {
		name string
		do   func(ctx context.Context) (string, error)
	}
	steps := []step{
		{store.MergeStepCoreReassign, r.coreReassign},
		{store.MergeStepAckTransfer, r.ackTransfer},
		{store.MergeStepWorkflowReassign, r.workflowReassign},
		{store.MergeStepIdentityPrefs, r.identityPrefs},
		{store.MergeStepSessionRevoke, r.sessionRevoke},
		{store.MergeStepTombstoneSource, r.tombstone},
	}
	def := domain.WorkflowDefinition{ID: workflowID, Version: 1, Name: "Account merge", Start: steps[0].name, Published: true}
	for i, st := range steps {
		next := "done"
		if i+1 < len(steps) {
			next = steps[i+1].name
		}
		def.Steps = append(def.Steps, domain.Step{ID: st.name, Type: domain.StepType("merge." + st.name), Next: next})
		sg.RegisterVerb("merge."+st.name, "common", verbs.HandlerFunc(func(ctx context.Context, _ domain.SagaRun, _ domain.Step) (map[string]any, error) {
			return nil, r.runStep(ctx, st.name, st.do)
		}))
	}
	def.Steps = append(def.Steps, domain.Step{ID: "done", Type: domain.StepTypeEnd})
	if err := sg.Register(def); err != nil {
		return nil, err
	}
	return sg, nil
}

// runStep skips a step the operation already completed, and records the
// outcome otherwise. A failure stops the saga.
func (r *mergeRun) runStep(ctx context.Context, name string, do func(context.Context) (string, error)) error {
	if r.op.StepStatus(name) == store.MergeStepCompleted {
		if name == store.MergeStepTombstoneSource {
			r.insertAuditStep(store.MergeStepCompleted, "already completed", "")
		}
		r.add(name, store.MergeStepCompleted, "already completed", "")
		return nil
	}
	detail, err := do(ctx)
	if err != nil {
		r.failed = true
		_ = r.o.store.SetMergeStep(ctx, r.op.ID, name, store.MergeStepFailed, "", err.Error())
		if name == store.MergeStepTombstoneSource {
			r.insertAuditStep(store.MergeStepFailed, "", err.Error())
		}
		r.add(name, store.MergeStepFailed, "", err.Error())
		return err
	}
	_ = r.o.store.SetMergeCounts(ctx, r.op.ID, r.counts.toMap())
	_ = r.o.store.SetMergeStep(ctx, r.op.ID, name, store.MergeStepCompleted, detail, "")
	if name == store.MergeStepTombstoneSource {
		const auditDetail = "user.accounts_merged emitted"
		_ = r.o.store.SetMergeStep(ctx, r.op.ID, store.MergeStepAuditEvent, store.MergeStepCompleted, auditDetail, "")
		r.insertAuditStep(store.MergeStepCompleted, auditDetail, "")
	}
	r.add(name, store.MergeStepCompleted, detail, "")
	return nil
}

func (r *mergeRun) add(step, status, detail, errStr string) {
	r.steps = append(r.steps, StepResult{Step: step, Status: status, Detail: detail, Error: errStr})
}

func (r *mergeRun) insertAuditStep(status, detail, errStr string) {
	r.add(store.MergeStepAuditEvent, status, detail, errStr)
}

func (r *mergeRun) coreReassign(ctx context.Context) (string, error) {
	_, owners, grants, err := r.o.core.ReassignUserPolicies(ctx, r.source, r.target, r.actorUserID)
	if err != nil {
		return "", err
	}
	r.counts.PoliciesOwned, r.counts.RaciGrants = owners, grants
	return fmt.Sprintf("re-owned %d policies, %d RACI grants", owners, grants), nil
}

func (r *mergeRun) ackTransfer(ctx context.Context) (string, error) {
	moved, deduped, _, err := r.o.ack.TransferAcknowledgments(ctx, r.source, r.target,
		ackTransferActor(r.actorUserID, r.actorExternal), false, r.op.ID.String())
	if err != nil {
		return "", err
	}
	r.counts.AcksMoved, r.counts.AcksDeduped = moved, deduped
	return fmt.Sprintf("moved %d acks, deduped %d", moved, deduped), nil
}

func (r *mergeRun) workflowReassign(ctx context.Context) (string, error) {
	reassigned, _, runs, err := r.o.wf.ReassignUserWorkflowItems(ctx, r.source, r.target, r.actorUserID, false, r.op.ID.String())
	if err != nil {
		return "", err
	}
	r.counts.WorkflowItems = reassigned + runs
	return fmt.Sprintf("reassigned %d approval seats, %d active runs", reassigned, runs), nil
}

func (r *mergeRun) identityPrefs(ctx context.Context) (string, error) {
	moved, err := r.o.store.MovePreferences(ctx, r.sID, r.tID)
	if err != nil {
		return "", err
	}
	r.counts.Preferences = moved
	return fmt.Sprintf("moved %d preferences", moved), nil
}

func (r *mergeRun) sessionRevoke(ctx context.Context) (string, error) {
	n, err := r.o.sessions.RevokeAccountSessions(ctx, r.sID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("revoked %d sessions", n), nil
}

func (r *mergeRun) tombstone(ctx context.Context) (string, error) {
	if err := r.o.store.TombstoneMergedSource(ctx, r.op.ID, r.sID, r.tID, r.actorPtr, r.actorExternal, r.counts.toMap()); err != nil {
		return "", err
	}
	return "source tombstoned (merged into target)", nil
}
