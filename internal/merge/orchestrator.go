// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package merge runs an admin account merge as a saga on
// go-saga-orchestration: it moves a source account's records onto a target
// account, then deletes the source, marked as merged into the target.
//
// The record moves go to the services that own them: core re-owns the
// source's policies and rewrites its category access rules, obligations
// transfers its acknowledgements, and workflow re-points its pending
// approvals. Identity moves preferences, revokes the source's sessions,
// writes one audit event naming both accounts, and deletes the source last,
// only after every move has succeeded.
//
// Every step is idempotent and the merge resumes: a failed step leaves the
// operation partial, and running it again with the same idempotency key skips
// the steps already completed.
package merge

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// ErrPrivilegedConfirmRequired is returned by Execute when the source is a root
// or site-admin account and the caller did not pass confirm_privileged. Mapped
// to FailedPrecondition by the handler.
var ErrPrivilegedConfirmRequired = errors.New("merging a root/site-admin source requires confirm_privileged")

// PolicyRef is a minimal policy identity for the preview (from core).
type PolicyRef struct {
	ID     string
	Number string
	Title  string
}

// PolicyVersionRef is one policy version resolved together with the identity of
// the policy it belongs to — enough to render a human label for an
// acknowledgement preview row (from core).
type PolicyVersionRef struct {
	ID           string
	PolicyID     string
	PolicyNumber string
	PolicyTitle  string
	VersionNo    int32
}

// AckItem is one acknowledgement transfer line (from the obligations service).
type AckItem struct {
	PolicyVersionID string
	Resolution      string // moved | kept_earliest | target_kept
	SourceAckedAt   time.Time
	TargetAckedAt   time.Time
}

// CoreClient is the subset of the core PolicyService the merge needs.
type CoreClient interface {
	ListPoliciesByOwner(ctx context.Context, ownerUserID string, includeRetired bool) ([]PolicyRef, error)
	ReassignUserPolicies(ctx context.Context, fromUserID, toUserID, actorUserID string) (policyIDs []string, ownerCount, authorGrants int, err error)
	// GetPolicyVersion resolves one policy version id to the version plus its
	// owning policy's number/title, so the preview can name the policy an
	// acknowledgement belongs to instead of showing a bare UUID. Used for display
	// only: callers treat a failure or an empty result as "unresolved".
	GetPolicyVersion(ctx context.Context, versionID string) (PolicyVersionRef, error)
}

// AckClient is the subset of the the obligations service AckService the merge needs.
type AckClient interface {
	TransferAcknowledgments(ctx context.Context, sourceUserID, targetUserID, actorUserID string, dryRun bool, mergeOperationID string) (moved, deduped int, items []AckItem, err error)
}

// WorkflowClient is the subset of the workflow WorkflowService the merge needs.
// ReassignUserWorkflowItems re-points the source's pending/paused approval seats
// and active-run submitter onto the target. It is idempotent and dry-run capable
// (dry_run=true mutates nothing and returns the counts the preview shows).
type WorkflowClient interface {
	ReassignUserWorkflowItems(ctx context.Context, fromUserID, toUserID, actorUserID string, dryRun bool, mergeOperationID string) (reassigned, deduped, runs int, err error)
}

// Item kinds surfaced in a preview.
const (
	KindPolicyOwner    = "policy_owner"
	KindRaciGrant      = "raci_grant"
	KindAcknowledgment = "acknowledgment"
	KindWorkflowItem   = "workflow_item"
	KindPreference     = "preference"
)

// Counts is the per-record-type tally shared by preview and result.
type Counts struct {
	PoliciesOwned int
	RaciGrants    int
	AcksMoved     int
	AcksDeduped   int
	WorkflowItems int
	Preferences   int
}

func (c Counts) toMap() map[string]any {
	return map[string]any{
		"policies_owned":          c.PoliciesOwned,
		"raci_grants":             c.RaciGrants,
		"acknowledgments_moved":   c.AcksMoved,
		"acknowledgments_deduped": c.AcksDeduped,
		"workflow_items":          c.WorkflowItems,
		"preferences":             c.Preferences,
	}
}

func countsFromMap(m map[string]any) Counts {
	get := func(k string) int {
		switch v := m[k].(type) {
		case float64:
			return int(v)
		case int:
			return v
		case int64:
			return int(v)
		default:
			return 0
		}
	}
	return Counts{
		PoliciesOwned: get("policies_owned"),
		RaciGrants:    get("raci_grants"),
		AcksMoved:     get("acknowledgments_moved"),
		AcksDeduped:   get("acknowledgments_deduped"),
		WorkflowItems: get("workflow_items"),
		Preferences:   get("preferences"),
	}
}

// PreviewItem is one human-reviewable line in the dry-run.
type PreviewItem struct {
	Kind   string
	RefID  string
	Label  string
	Detail string
}

// Warning flags a condition the admin should weigh before executing.
type Warning struct {
	Code    string
	Message string
}

// Preview is the read-only dry-run result.
type Preview struct {
	SourceUserID              string
	TargetUserID              string
	Counts                    Counts
	Items                     []PreviewItem
	Warnings                  []Warning
	RequiresPrivilegedConfirm bool
}

// StepResult reports one orchestrated step's outcome.
type StepResult struct {
	Step   string
	Status string // completed | failed | skipped | pending
	Detail string
	Error  string
}

// Result is the execute outcome.
type Result struct {
	MergeOperationID string
	Status           string // completed | partial | failed
	Counts           Counts
	Steps            []StepResult
}

// SessionRevoker ends every session of an account; the service revokes
// them in Kratos.
type SessionRevoker interface {
	RevokeAccountSessions(ctx context.Context, userID uuid.UUID) (int, error)
}

// Orchestrator coordinates a merge across identity, core, obligations and
// workflow.
type Orchestrator struct {
	store    *store.Store
	core     CoreClient
	ack      AckClient
	wf       WorkflowClient
	sessions SessionRevoker
}

// New builds an Orchestrator. A nil core, ack, wf or sessions makes Preview
// and Execute fail instead of skipping a step, so nothing is lost.
func New(s *store.Store, core CoreClient, ack AckClient, wf WorkflowClient, sessions SessionRevoker) *Orchestrator {
	return &Orchestrator{store: s, core: core, ack: ack, wf: wf, sessions: sessions}
}

func ackDetail(resolution string) string {
	switch resolution {
	case "moved":
		return "moved to target"
	case "kept_earliest":
		return "both acked — kept earliest"
	case "target_kept":
		return "both acked — target already satisfied"
	default:
		return "moved to target"
	}
}

// policyVersionLabel renders a resolved policy version as display text, in the
// same shape as the policy-owner preview row ("NUMBER — TITLE", em-dash, number
// alone when the title is empty) plus the version number, because
// acknowledgement rows are per-VERSION rather than per-policy:
//
//	POL-ENG-000012 — Acceptable Use Policy (v3)
//
// Returns "" when the ref carries no policy number, i.e. nothing usable was
// resolved; the caller then falls back to the raw id.
func policyVersionLabel(ref PolicyVersionRef) string {
	if ref.PolicyNumber == "" {
		return ""
	}
	label := ref.PolicyNumber
	if ref.PolicyTitle != "" {
		label = ref.PolicyNumber + " — " + ref.PolicyTitle
	}
	if ref.VersionNo > 0 {
		label = fmt.Sprintf("%s (v%d)", label, ref.VersionNo)
	}
	return label
}

// resolvePolicyVersionLabels resolves the DISTINCT policy version ids in items
// to display labels (several acknowledgements commonly point at the same
// version, and core is called once per version, not once per row).
//
// Resolution is best-effort and never returns an error: an id whose lookup
// fails or resolves to nothing maps to "", and the caller substitutes the raw
// id. A label is cosmetic relative to the merge's correctness, so a degraded
// core must not fail the preview.
func (o *Orchestrator) resolvePolicyVersionLabels(ctx context.Context, items []AckItem) map[string]string {
	labels := make(map[string]string, len(items))
	if o.core == nil {
		return labels
	}
	for _, it := range items {
		if it.PolicyVersionID == "" {
			continue
		}
		if _, attempted := labels[it.PolicyVersionID]; attempted {
			continue
		}
		// Recorded before the call so a failing id is attempted once too, rather
		// than re-hammering an already-degraded core for every row.
		labels[it.PolicyVersionID] = ""
		ref, err := o.core.GetPolicyVersion(ctx, it.PolicyVersionID)
		if err != nil {
			continue
		}
		labels[it.PolicyVersionID] = policyVersionLabel(ref)
	}
	return labels
}

// ackPreviewItems builds the acknowledgement rows of the preview's review list,
// naming the policy each acknowledgement belongs to where core can resolve it
// and falling back to the raw version id where it cannot. Every input item
// yields exactly one row with a non-empty label, so the list the admin reviews
// always matches the counts reported next to it.
//
// RefID stays the raw PolicyVersionID: it is the row key and is machine-facing.
func (o *Orchestrator) ackPreviewItems(ctx context.Context, items []AckItem) []PreviewItem {
	labels := o.resolvePolicyVersionLabels(ctx, items)
	out := make([]PreviewItem, 0, len(items))
	for _, it := range items {
		label := labels[it.PolicyVersionID]
		if label == "" {
			label = "Policy version " + it.PolicyVersionID
		}
		out = append(out, PreviewItem{Kind: KindAcknowledgment, RefID: it.PolicyVersionID, Label: label, Detail: ackDetail(it.Resolution)})
	}
	return out
}

// Preview computes, WITHOUT mutating anything, exactly what a merge would move.
func (o *Orchestrator) Preview(ctx context.Context, sourceID, targetID string) (*Preview, error) {
	if o.core == nil || o.ack == nil || o.wf == nil {
		return nil, ErrNotConfigured
	}
	sID, err := uuid.Parse(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: source_user_id", store.ErrInvalid)
	}
	tID, err := uuid.Parse(targetID)
	if err != nil {
		return nil, fmt.Errorf("%w: target_user_id", store.ErrInvalid)
	}
	parties, err := o.store.MergePreflight(ctx, sID, tID)
	if err != nil {
		return nil, err
	}

	p := &Preview{SourceUserID: sourceID, TargetUserID: targetID}
	if !parties.Target.Enabled {
		p.Warnings = append(p.Warnings, Warning{Code: "TARGET_DISABLED", Message: "the target account is disabled"})
	}
	if parties.SourceIsRoot {
		p.Warnings = append(p.Warnings, Warning{Code: "SOURCE_IS_ROOT", Message: "the source is the protected root account; it cannot be merged away"})
		p.RequiresPrivilegedConfirm = true
	}
	if parties.SourceIsSiteAdmin {
		p.Warnings = append(p.Warnings, Warning{Code: "SOURCE_IS_SITE_ADMIN", Message: "the source is a site-admin account; extra confirmation required"})
		p.RequiresPrivilegedConfirm = true
	}

	// Owned policies + RACI (core). owner_user_id IS the RACI author in this
	// system, so each owned policy carries its author grant; the user's other
	// user-subject category RACI rules are rewritten on execute (exact count
	// reported then).
	policies, err := o.core.ListPoliciesByOwner(ctx, sourceID, true)
	if err != nil {
		return nil, err
	}
	p.Counts.PoliciesOwned = len(policies)
	for _, pol := range policies {
		label := pol.Number
		if pol.Title != "" {
			label = pol.Number + " — " + pol.Title
		}
		p.Items = append(p.Items, PreviewItem{Kind: KindPolicyOwner, RefID: pol.ID, Label: label, Detail: "owner"})
	}
	if len(policies) > 0 {
		p.Items = append(p.Items, PreviewItem{Kind: KindRaciGrant, RefID: "", Label: "Category RACI grants", Detail: "user-subject category rules will be reassigned to the target"})
	}

	// Acknowledgements (the obligations service) — dry-run, so counts/items are exact.
	moved, deduped, items, err := o.ack.TransferAcknowledgments(ctx, sourceID, targetID, "", true, "")
	if err != nil {
		return nil, err
	}
	p.Counts.AcksMoved = moved
	p.Counts.AcksDeduped = deduped
	p.Items = append(p.Items, o.ackPreviewItems(ctx, items)...)

	// Preferences (local) — moved only where the target has none.
	if parties.Target.Timezone == "" && parties.Source.Timezone != "" {
		p.Counts.Preferences++
		p.Items = append(p.Items, PreviewItem{Kind: KindPreference, RefID: "timezone", Label: "Timezone", Detail: parties.Source.Timezone})
	}
	if parties.Target.Locale == "" && parties.Source.Locale != "" {
		p.Counts.Preferences++
		p.Items = append(p.Items, PreviewItem{Kind: KindPreference, RefID: "locale", Label: "Locale", Detail: parties.Source.Locale})
	}

	// Workflow in-flight items (workflow) — dry-run, so counts are exact. The
	// tally is the source's pending/paused approval seats plus the active runs it
	// submitted; both are re-pointed to the target on execute.
	wfReassigned, _, wfRuns, err := o.wf.ReassignUserWorkflowItems(ctx, sourceID, targetID, "", true, "")
	if err != nil {
		return nil, err
	}
	p.Counts.WorkflowItems = wfReassigned + wfRuns
	if p.Counts.WorkflowItems > 0 {
		p.Items = append(p.Items, PreviewItem{Kind: KindWorkflowItem, RefID: "", Label: "In-flight workflow items", Detail: fmt.Sprintf("%d approval seat(s), %d active run(s) reassigned to the target", wfReassigned, wfRuns)})
	}
	return p, nil
}

// Execute runs the merge. A root source is refused; a site-admin source
// needs confirmPrivileged. The idempotency key defaults to one derived from
// the two accounts, so a repeated call resumes the same operation.
func (o *Orchestrator) Execute(ctx context.Context, sourceID, targetID, actorUserID, actorExternal string, confirmPrivileged bool, idempotencyKey string) (*Result, error) {
	if o.core == nil || o.ack == nil || o.wf == nil || o.sessions == nil {
		return nil, ErrNotConfigured
	}
	sID, err := uuid.Parse(sourceID)
	if err != nil {
		return nil, fmt.Errorf("%w: source_user_id", store.ErrInvalid)
	}
	tID, err := uuid.Parse(targetID)
	if err != nil {
		return nil, fmt.Errorf("%w: target_user_id", store.ErrInvalid)
	}
	parties, err := o.store.MergePreflight(ctx, sID, tID)
	if err != nil {
		return nil, err
	}
	if parties.SourceIsRoot {
		return nil, fmt.Errorf("%w: cannot merge away the root account", store.ErrRootProtected)
	}
	if parties.SourceIsSiteAdmin && !confirmPrivileged {
		return nil, ErrPrivilegedConfirmRequired
	}

	key := idempotencyKey
	if key == "" {
		key = "merge:" + sourceID + "->" + targetID
	}
	var actorPtr *uuid.UUID
	if actorUserID != "" {
		if id, e := uuid.Parse(actorUserID); e == nil {
			actorPtr = &id
		}
	}
	op, err := o.store.BeginMergeOperation(ctx, key, sID, tID, actorPtr, actorExternal)
	if err != nil {
		return nil, err
	}

	run := &mergeRun{
		o: o, op: op, sID: sID, tID: tID, source: sourceID, target: targetID,
		actorUserID: actorUserID, actorExternal: actorExternal, actorPtr: actorPtr,
		counts: countsFromMap(op.Counts),
	}
	sg, err := run.saga()
	if err != nil {
		return nil, err
	}
	// A linear saga advances inside Start on this context, so the steps'
	// outbound calls carry the caller and the act-as admin.
	// A failed step stops the saga and is reported as a partial merge; any
	// other saga error is the engine's own.
	if _, err := sg.Start(ctx, workflowID, nil); err != nil && !run.failed {
		return nil, fmt.Errorf("merge saga: %w", err)
	}
	res := &Result{MergeOperationID: op.ID.String(), Counts: run.counts, Steps: run.steps}
	for _, st := range stepOrder[len(run.steps):] {
		res.Steps = append(res.Steps, StepResult{Step: st, Status: store.MergeStepPending, Detail: "not run: a prior step failed"})
	}
	if run.failed {
		_ = o.store.SetMergeStatus(ctx, op.ID, store.MergeOpPartial)
		res.Status = store.MergeOpPartial
	} else {
		res.Status = store.MergeOpCompleted
	}
	return res, nil
}

// ackTransferActor resolves the actor identity to send to the obligations service's
// TransferAcknowledgments.
//
// the obligations service REQUIRES a non-empty actor on a real (non-dry-run) transfer
// (ACK_TRANSFER_ACTOR_REQUIRED, Code 7006): an acknowledgment is a legal
// attestation, so moving one between accounts has to record who authorised the
// move. Its ack.transferred audit event takes the actor from that field and
// nothing else.
//
// AdminAuth.Authorize resolves the admin down two mutually exclusive paths, and
// only one of them fills ActorUserID:
//
//   - gateway path (site-admin via GraphQL): ActorUserID is the admin's
//     platform user uuid;
//   - admin CLI path (mTLS SPIFFE ID match, an operator on the admin CLI):
//     ActorUserID is EMPTY and the human is identified solely by ActorExternal,
//     the x-audit-operator label such as "alice@<fingerprint>".
//
// Passing actorUserID alone would send "" on every CLI merge, which the
// obligations service refuses: an acknowledgement transfer must name who
// authorised it. Falling back to the label makes the admin CLI path
// attributable.
//
// Deliberately NOT used for the core and workflow reassign calls in Execute:
// core's ReassignUserPolicies validates actor_user_id with parseOptionalUUID
// and would reject an operator label, failing the whole merge. Those two carry
// the same empty-actor gap on the admin CLI path, but closing it needs a contract
// change on their side.
func ackTransferActor(actorUserID, actorExternal string) string {
	if actorUserID != "" {
		return actorUserID
	}
	return actorExternal
}
