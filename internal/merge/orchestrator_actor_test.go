// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package merge

import "testing"

// These tests cover the actor identity the merge orchestrator sends to
// the obligations service's TransferAcknowledgments.
//
// made a non-empty actor mandatory on a real transfer
// (ACK_TRANSFER_ACTOR_REQUIRED, Code 7006), because an acknowledgment is a
// legal attestation and moving one between accounts must record who authorised
// it. Auditing this caller for that change turned up a second defect: the
// orchestrator passed actorUserID straight through, and on the TOOLBOX (mTLS)
// admin path AdminAuth.Authorize leaves ActorUserID empty by construction —
// the human is identified only by ActorExternal, the x-audit-operator label. So
// every CLI-driven merge emitted an ack.transferred naming nobody, while
// identity's own audit trail for the same merge kept the operator label.
//
// The resolution is deliberately a pure function so it is testable without a
// Postgres-backed store: the merge tests in internal/handlers are integration
// tests gated on DATABASE_TEST_DSN, which means the admin CLI path's attribution
// would otherwise only ever be exercised in CI.

func TestAckTransferActor_GatewayPathUsesPlatformUserID(t *testing.T) {
	const adminUUID = "6f1c1e2a-0000-4000-8000-000000000001"
	if got := ackTransferActor(adminUUID, ""); got != adminUUID {
		t.Errorf("ackTransferActor = %q, want the admin's platform user id %q", got, adminUUID)
	}
}

// TestAckTransferActor_ToolboxPathFallsBackToOperatorLabel is the defect. An
// empty ActorUserID with an operator label present must resolve to the label,
// not to "".
func TestAckTransferActor_ToolboxPathFallsBackToOperatorLabel(t *testing.T) {
	const operator = "alice@ab12cd34"
	got := ackTransferActor("", operator)
	if got == "" {
		t.Fatal("ackTransferActor returned empty on the admin CLI path: the obligations service " +
			"rejects the transfer (Code 7006) and, before it did, emitted an " +
			"ack.transferred attributed to nobody")
	}
	if got != operator {
		t.Errorf("ackTransferActor = %q, want the operator label %q", got, operator)
	}
}

// TestAckTransferActor_PrefersUserIDOverLabel pins precedence. The two are
// mutually exclusive in practice, but if both are ever set the platform user id
// is the more useful identifier and must win.
func TestAckTransferActor_PrefersUserIDOverLabel(t *testing.T) {
	if got := ackTransferActor("u-1", "alice@ab12cd34"); got != "u-1" {
		t.Errorf("ackTransferActor = %q, want %q", got, "u-1")
	}
}

// TestAckTransferActor_BothEmptyStaysEmpty documents that this helper does not
// invent an actor. Both paths of AdminAuth.Authorize populate exactly one of
// the two fields, so reaching here means authorization did not resolve an
// actor at all — and the obligations service rejecting the transfer is the correct
// outcome, rather than a synthesized "system" actor quietly standing in for a
// human on a legal attestation.
func TestAckTransferActor_BothEmptyStaysEmpty(t *testing.T) {
	if got := ackTransferActor("", ""); got != "" {
		t.Errorf("ackTransferActor = %q, want \"\" — no actor must never be "+
			"papered over with a synthetic one on an attestation transfer", got)
	}
}
