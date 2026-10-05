// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package userdelete holds the cross-service PRE-DELETE guard for
// IdentityAdminService.DeleteUser.
//
// # The problem
//
// Deleting a user tombstones the identity row and cleans every access row
// INSIDE the identity database, but a user is also referenced by other
// services. MergeAccounts (internal/merge) handles those references by MOVING
// them, because a merge has a target account to move them to. A delete has no
// target, so "reassign" is not available and each class of reference needs its
// own deliberate answer. Verified in prod on 2026-09-15 after a real delete,
// three classes were left dangling:
//
//  1. kratos.identities — the account's Kratos identity stayed state=active
//     with a working `password` credential. ANSWER: revoke it, unconditionally,
//     before the tombstone (see internal/kratosadmin). There is no reason a
//     deleted account keeps a credential, so this needs no operator decision.
//
//  2. workflow.approval_assignments — two PENDING stage-0 approval seats stayed
//     assigned to the deleted account, each the ONLY assignee on its stage.
//     That silently made two prod policies unapprovable by anyone for a month;
//     they had to be recovered by withdrawing the reviews. ANSWER: REFUSE the
//     delete and name the affected policies. Rationale below.
//
//  3. core.category_rules — a user-subject RACI rule survived as dead config.
//     ANSWER: delete the account's own user-subject rules with the account and
//     audit the removal (see the note at the bottom of this comment).
//
// # Why the workflow class is a refusal, not an auto-release
//
// The alternatives were (a) refuse while the account holds pending approvals,
// (b) auto-release the seat back to its stage, (c) terminate the seat the way a
// withdraw does. (b) and (c) both have a delete quietly mutate a live approval
// workflow: releasing a seat re-opens an assignment decision (to whom? the
// stage's approver_groups may be large, or empty), and terminating one is a
// policy-level outcome — a withdraw is a reviewer's decision that rolls the
// version back to draft, not a side effect of admin user management. Either
// would leave a policy in a state nobody chose, with the admin who clicked
// "delete user" as the only, uninformative audit trail.
//
// A refusal is the only option that keeps the human in the loop on an approval
// decision while still making the stranded-seat outcome IMPOSSIBLE rather than
// merely unlikely. It is also honest about what identity knows: identity cannot
// see a stage's eligibility rules, so it cannot pick a successor, but workflow
// already exposes both remedies (SwapAssignee to reassign, Signal/withdraw to
// end the review). The refusal names the exact policies so the admin can act
// without hunting, and Disable account remains available for the urgent case
// (it locks the user out immediately and leaves the seats reassignable).
//
// Refusing also needs no new downstream contract: the check is the existing
// workflow ListPendingTasks RPC. Options (b) and (c) would each require a new
// workflow RPC to release or terminate a seat with no target user.
//
// # Fail closed
//
// All three steps are MANDATORY. If the approval check cannot run, the delete
// is refused rather than performed blind — proceeding blind is exactly what
// produced the prod incident. If the credential revoke fails, the delete is
// refused rather than tombstoning an account whose password still works. If the
// category-rule purge cannot run, the delete is refused rather than tombstoning
// an account that leaves live grants behind. This mirrors the merge
// orchestrator, which never tombstones a source before its records have
// actually moved.
//
// An unwired client is a refusal, never a skip. That matters most for the
// purge: unlike a stranded approval seat, which eventually surfaces as a policy
// nobody can approve, a dead grant surfaces as nothing at all — so "best
// effort" would silently reproduce the defect.
//
// # Why the order is approvals -> revoke -> purge
//
// The refusal comes first so an admin told to reassign approvals does not
// discover that the account has meanwhile been changed. The credential revoke
// comes before the purge because of what each failure leaves behind: if the
// purge is unavailable, the account is locked out but otherwise INTACT (which
// is what an admin reaching for Delete wanted anyway, and retrying is safe
// because the purge is idempotent); if the order were reversed, a Kratos outage
// would leave an account that still works but has silently lost its category
// grants — an access change nobody asked for, on a user who still exists.
//
// # The RACI class: core.category_rules
//
// The decision for the RACI class is to DELETE the user's user-subject category
// rules with the account and audit the removal (a rule naming a nonexistent
// user is dead config that a future reader will trust, and a grant is
// re-creatable whereas a stranded approval is not). It could not be implemented
// when this guard was written, because core exposed no way to say it: the only
// mutating surface was GroupService.SetCategoryRuleset, per-category
// read-modify-write, and the only bulk path was
// PolicyService.ReassignUserPolicies, which REQUIRES a valid to_user_id that
// differs from from_user_id — a delete has none.
//
// added GroupService.PurgeUserCategoryRules, and it is the third step
// below (CategoryRulePurger). Its scope is exactly the deleted account's OWN
// user-subject rules: group- and everyone-subject rules are untouched, and so
// is every record that merely names the user as the actor who did something —
// policy ownership, version authorship, approval history, audit rows. Deleting
// a user does not un-write history, and identity deliberately asks for nothing
// wider.
//
// Still open: MergeAccounts has the same blind spot from the other side.
// ReassignUserPolicies rewrites a user-subject rule's subject_ref, so a merge
// does move the grants, but only PolicyService owns that sweep and it needs a
// target — whether a merged-away source should also be purge-able is the same
// conversation, tracked on.
//
// # What is NOT handled here: the pre-delete preview
//
// A dry run (the delete-side equivalent of previewAccountMerge) is.
// The refusal above already carries the affected-policy list, so the dangerous
// outcome is prevented rather than merely warned about; the preview adds the
// up-front visibility for the classes that are NOT refusals.
package userdelete

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

// Step names, carried as the {step} metadata on the coded refusal so an
// operator is told which backend to look at.
const (
	StepApprovalCheck     = "approval_check"
	StepCredentialRevoke  = "credential_revoke" // #nosec G101 -- a step name
	StepCategoryRulePurge = "category_rule_purge"
)

// PendingApproval is one approval seat the account still holds and has not
// acted on — a stage waiting for a decision from this user.
type PendingApproval struct {
	TaskID          string
	RunID           string
	PolicyVersionID string
	PolicyTitle     string
	StageIndex      int32
	DueAt           time.Time
}

// ApprovalLister reads the account's outstanding approval seats from workflow.
// Backed by WorkflowService.ListPendingTasks (see NewGRPCApprovalLister); a
// fake satisfies it in tests.
type ApprovalLister interface {
	ListPendingApprovals(ctx context.Context, userID string) ([]PendingApproval, error)
}

// CredentialRevoker revokes the account's local-login credential in the
// credential store. *kratos.Client satisfies it.
type CredentialRevoker interface {
	RevokeIdentity(ctx context.Context, email string) (kratos.RevokeResult, error)
}

// PurgeResult reports what the category-rule purge removed, for the audit
// trail. RemovedRules=0 with no affected categories is a perfectly normal
// outcome: most accounts hold no user-subject RACI rules at all.
type PurgeResult struct {
	RemovedRules        int
	AffectedCategoryIDs []string
}

// CategoryRulePurger removes the account's own user-subject category RACI rules
// in core. Backed by GroupService.PurgeUserCategoryRules (see
// NewGRPCCategoryRulePurger); a fake satisfies it in tests.
//
// There is no to_user_id: a delete has no target account, which is the whole
// reason exists. Reassignment is MergeAccounts' job (internal/merge).
type CategoryRulePurger interface {
	PurgeUserCategoryRules(ctx context.Context, userID, actorUserID string) (PurgeResult, error)
}

// Steps holds the clients the pre-delete guard drives, one per mandatory step.
// A struct rather than positional parameters because the steps are an ORDERED,
// growing list (three as of and a nil field has a specific meaning —
// not "skip", but "refuse, this deployment cannot run the step".
type Steps struct {
	Approvals     ApprovalLister
	Credentials   CredentialRevoker
	CategoryRules CategoryRulePurger
}

// Target identifies the account being deleted and the admin deleting it. A
// struct because the three values are all strings and getting them the wrong
// way round positionally would send the purge at the wrong account. ActorUserID
// is empty on the admin CLI (mTLS) path, which has no platform user; downstream
// audit records it as unattributed rather than guessing.
type Target struct {
	UserID      string
	Email       string
	ActorUserID string
}

// PendingApprovalsError refuses the delete because the account is the assigned
// approver on approvals that are still awaiting a decision. Mapped by the
// handler to errcodes.UserHasPendingApprovals (5008).
type PendingApprovalsError struct {
	Items []PendingApproval
}

func (e *PendingApprovalsError) Error() string {
	return fmt.Sprintf("user holds %d pending approval assignment(s): %s",
		len(e.Items), DescribeApprovals(e.Items, len(e.Items)))
}

// StepUnavailableError refuses the delete because a mandatory pre-delete step
// could not be completed at all — its client is not wired, or the downstream
// call failed. Mapped by the handler to errcodes.UserDeleteChecksUnavailable
// (5009). NOTHING has been written when this is returned by the approval check;
// when it is returned by the credential revoke the identity row is still
// untouched, so a retry is safe either way.
type StepUnavailableError struct {
	Step string
	Err  error
}

func (e *StepUnavailableError) Error() string {
	return fmt.Sprintf("pre-delete step %q unavailable: %v", e.Step, e.Err)
}

func (e *StepUnavailableError) Unwrap() error { return e.Err }

// Result reports the guard's outcome for the audit trail. It is only returned
// when the delete may proceed.
type Result struct {
	// Revoke is what the credential store actually did. Revoke.Found=false is a
	// legitimate outcome (a federated/SSO-only account has no local credential).
	Revoke kratos.RevokeResult
	// Purge is what the category-rule purge removed in core.
	Purge PurgeResult
}

// Check runs all three mandatory pre-delete steps, in order, and reports
// whether the delete may proceed.
//
//  1. Outstanding approvals — a non-empty result is a REFUSAL
//     (*PendingApprovalsError). Run first so a refused delete never touches the
//     account's credential: an admin who is told to reassign approvals first
//     must not discover that the user has meanwhile been locked out.
//  2. Credential revoke — unconditional once step 1 passes, and performed
//     BEFORE the caller writes the tombstone, so a failure here leaves a live
//     account rather than a tombstoned one with a working password.
//  3. Category-rule purge — removes the account's own user-subject
//     RACI rules in core. Last, because it is the step whose failure is least
//     harmful to leave for a retry: see the ordering note in the package doc.
//
// A nil client on ANY step is a *StepUnavailableError, not a skip.
func Check(ctx context.Context, steps Steps, target Target) (Result, error) {
	if steps.Approvals == nil {
		return Result{}, &StepUnavailableError{Step: StepApprovalCheck, Err: errors.New("workflow client not configured")}
	}
	pending, err := steps.Approvals.ListPendingApprovals(ctx, target.UserID)
	if err != nil {
		return Result{}, &StepUnavailableError{Step: StepApprovalCheck, Err: err}
	}
	if len(pending) > 0 {
		return Result{}, &PendingApprovalsError{Items: pending}
	}

	if steps.Credentials == nil {
		return Result{}, &StepUnavailableError{Step: StepCredentialRevoke, Err: errors.New("credential store not configured")}
	}
	rev, err := steps.Credentials.RevokeIdentity(ctx, target.Email)
	if err != nil {
		return Result{}, &StepUnavailableError{Step: StepCredentialRevoke, Err: err}
	}

	if steps.CategoryRules == nil {
		return Result{}, &StepUnavailableError{Step: StepCategoryRulePurge, Err: errors.New("core client not configured")}
	}
	purge, err := steps.CategoryRules.PurgeUserCategoryRules(ctx, target.UserID, target.ActorUserID)
	if err != nil {
		return Result{Revoke: rev}, &StepUnavailableError{Step: StepCategoryRulePurge, Err: err}
	}
	return Result{Revoke: rev, Purge: purge}, nil
}

// maxNamedApprovals bounds how many policies the refusal message names inline.
// The full list always rides in the error's Items (and the coded metadata), but
// a user-facing message has to stay readable.
const maxNamedApprovals = 5

// DescribeApprovals renders up to limit approvals as the human list the refusal
// shows: `"Backup and Recovery" (stage 1, due 2026-08-13)`, comma-separated,
// with a trailing "and N more" when truncated. A title-less version falls back
// to its version id so a row is never rendered as nothing.
func DescribeApprovals(items []PendingApproval, limit int) string {
	if limit <= 0 || limit > maxNamedApprovals {
		limit = maxNamedApprovals
	}
	parts := make([]string, 0, limit)
	for i, it := range items {
		if i == limit {
			break
		}
		label := strings.TrimSpace(it.PolicyTitle)
		if label == "" {
			label = "policy version " + it.PolicyVersionID
		}
		// StageIndex is 0-based on the wire; humans count stages from 1.
		detail := fmt.Sprintf("stage %d", it.StageIndex+1)
		if !it.DueAt.IsZero() {
			detail += ", due " + it.DueAt.UTC().Format("2006-01-02")
		}
		parts = append(parts, fmt.Sprintf("%q (%s)", label, detail))
	}
	out := strings.Join(parts, ", ")
	if extra := len(items) - len(parts); extra > 0 {
		out += fmt.Sprintf(" and %d more", extra)
	}
	return out
}
