// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"context"
	"errors"
	"testing"
)

// These tests cover the human label on the account-merge preview's
// acknowledgment rows.
//
// The preview is the ONLY view an admin gets of what an irreversible merge will
// do, and its acknowledgment rows used to render as `Policy version
// 6e8513b8-...`: a bare UUID that makes the review step impossible to actually
// perform. The rows now resolve to the same `NUMBER — TITLE` shape the sibling
// policy-owner row uses, plus the version number (ack rows are per-VERSION,
// unlike the policy-owner rows).
//
// Resolution is best-effort by design. A label is cosmetic relative to the
// merge's correctness, so a degraded core must never drop a row, blank a label,
// or fail the preview — it falls back to the original UUID string. The row
// count the admin sees has to match the counts reported alongside it.
//
// ackPreviewItems takes only o.core, so these are unit tests: the merge tests
// in internal/handlers are integration tests gated on DATABASE_TEST_DSN, which
// would otherwise leave the degraded path exercised only in CI.

// labelFakeCore implements CoreClient for the label tests. It records which
// version ids were looked up (and how many times) so the distinct-resolution
// guarantee is provable, and can fail every lookup to drive the degraded path.
type labelFakeCore struct {
	versions map[string]PolicyVersionRef
	err      error
	calls    []string
}

func (f *labelFakeCore) ListPoliciesByOwner(_ context.Context, _ string, _ bool) ([]PolicyRef, error) {
	return nil, nil
}

func (f *labelFakeCore) ReassignUserPolicies(_ context.Context, _, _, _ string) ([]string, int, int, error) {
	return nil, 0, 0, nil
}

func (f *labelFakeCore) GetPolicyVersion(_ context.Context, versionID string) (PolicyVersionRef, error) {
	f.calls = append(f.calls, versionID)
	if f.err != nil {
		return PolicyVersionRef{}, f.err
	}
	return f.versions[versionID], nil
}

func (f *labelFakeCore) callsFor(versionID string) int {
	n := 0
	for _, c := range f.calls {
		if c == versionID {
			n++
		}
	}
	return n
}

func labelOrchestrator(core CoreClient) *Orchestrator {
	return &Orchestrator{core: core}
}

// TestAckPreviewItems_ResolvesPolicyNumberTitleAndVersion is the defect: the
// row must name the policy, in the policy-owner row's format (em-dash), with
// the version number appended.
func TestAckPreviewItems_ResolvesPolicyNumberTitleAndVersion(t *testing.T) {
	const versionID = "6e8513b8-53cf-42dc-895b-55f51e1a96b5"
	core := &labelFakeCore{versions: map[string]PolicyVersionRef{
		versionID: {ID: versionID, PolicyID: "p-1", PolicyNumber: "POL-ENG-000012", PolicyTitle: "Acceptable Use Policy", VersionNo: 3},
	}}
	items := labelOrchestrator(core).ackPreviewItems(context.Background(),
		[]AckItem{{PolicyVersionID: versionID, Resolution: "moved"}})

	if len(items) != 1 {
		t.Fatalf("got %d preview rows, want 1", len(items))
	}
	const want = "POL-ENG-000012 — Acceptable Use Policy (v3)"
	if items[0].Label != want {
		t.Errorf("Label = %q, want %q — an admin cannot review a merge from a raw UUID", items[0].Label, want)
	}
	if items[0].RefID != versionID {
		t.Errorf("RefID = %q, want the raw policy version id %q: RefID is the row key and is machine-facing", items[0].RefID, versionID)
	}
	if items[0].Kind != KindAcknowledgment {
		t.Errorf("Kind = %q, want %q", items[0].Kind, KindAcknowledgment)
	}
	if items[0].Detail != ackDetail("moved") {
		t.Errorf("Detail = %q, want %q", items[0].Detail, ackDetail("moved"))
	}
}

// TestAckPreviewItems_EmptyTitleRendersNumberOnly mirrors the policy-owner row
// at orchestrator.go:243, which drops the em-dash when the title is empty
// rather than rendering a dangling separator.
func TestAckPreviewItems_EmptyTitleRendersNumberOnly(t *testing.T) {
	const versionID = "b1f0a2c3-0000-4000-8000-000000000001"
	core := &labelFakeCore{versions: map[string]PolicyVersionRef{
		versionID: {ID: versionID, PolicyNumber: "POL-ENG-000012", PolicyTitle: "", VersionNo: 3},
	}}
	items := labelOrchestrator(core).ackPreviewItems(context.Background(),
		[]AckItem{{PolicyVersionID: versionID, Resolution: "moved"}})

	const want = "POL-ENG-000012 (v3)"
	if items[0].Label != want {
		t.Errorf("Label = %q, want %q — an untitled policy must not render a dangling em-dash", items[0].Label, want)
	}
}

// TestAckPreviewItems_ResolvesDistinctIDsOnce pins the N-calls guarantee:
// several acknowledgments commonly point at the SAME policy version, and the
// preview must not issue a core lookup per row.
func TestAckPreviewItems_ResolvesDistinctIDsOnce(t *testing.T) {
	const (
		vA = "aaaaaaaa-0000-4000-8000-000000000001"
		vB = "bbbbbbbb-0000-4000-8000-000000000002"
	)
	core := &labelFakeCore{versions: map[string]PolicyVersionRef{
		vA: {ID: vA, PolicyNumber: "POL-ENG-000012", PolicyTitle: "Acceptable Use Policy", VersionNo: 3},
		vB: {ID: vB, PolicyNumber: "POL-HR-000004", PolicyTitle: "Code of Conduct", VersionNo: 1},
	}}
	items := labelOrchestrator(core).ackPreviewItems(context.Background(), []AckItem{
		{PolicyVersionID: vA, Resolution: "moved"},
		{PolicyVersionID: vB, Resolution: "kept_earliest"},
		{PolicyVersionID: vA, Resolution: "target_kept"},
	})

	if len(items) != 3 {
		t.Fatalf("got %d preview rows, want 3: every acknowledgment is its own reviewable row", len(items))
	}
	if got := core.callsFor(vA); got != 1 {
		t.Errorf("GetPolicyVersion(%s) called %d times, want 1 — resolve DISTINCT ids only", vA, got)
	}
	if got := len(core.calls); got != 2 {
		t.Errorf("GetPolicyVersion called %d times total, want 2 (one per distinct id)", got)
	}
	if items[0].Label != items[2].Label {
		t.Errorf("rows for the same version got different labels: %q vs %q", items[0].Label, items[2].Label)
	}
	if want := "POL-HR-000004 — Code of Conduct (v1)"; items[1].Label != want {
		t.Errorf("items[1].Label = %q, want %q", items[1].Label, want)
	}
}

// TestAckPreviewItems_CoreErrorFallsBackToUUID is the degraded path. Core being
// unreachable must not cost the admin a row, a count, or the whole preview: the
// label is cosmetic relative to the merge's correctness, so every row survives
// with the original UUID string.
func TestAckPreviewItems_CoreErrorFallsBackToUUID(t *testing.T) {
	const (
		vA = "aaaaaaaa-0000-4000-8000-000000000001"
		vB = "bbbbbbbb-0000-4000-8000-000000000002"
	)
	core := &labelFakeCore{err: errors.New("core unavailable")}
	in := []AckItem{
		{PolicyVersionID: vA, Resolution: "moved"},
		{PolicyVersionID: vB, Resolution: "kept_earliest"},
		{PolicyVersionID: vA, Resolution: "target_kept"},
	}
	items := labelOrchestrator(core).ackPreviewItems(context.Background(), in)

	if len(items) != len(in) {
		t.Fatalf("got %d preview rows, want %d: a degraded core must never drop a row from the review list", len(items), len(in))
	}
	for i, it := range items {
		if it.Label == "" {
			t.Fatalf("items[%d].Label is empty: the preview must never render a blank label", i)
		}
		if want := "Policy version " + it.RefID; it.Label != want {
			t.Errorf("items[%d].Label = %q, want the UUID fallback %q", i, it.Label, want)
		}
		if it.RefID != in[i].PolicyVersionID {
			t.Errorf("items[%d].RefID = %q, want %q", i, it.RefID, in[i].PolicyVersionID)
		}
		if it.Detail != ackDetail(in[i].Resolution) {
			t.Errorf("items[%d].Detail = %q, want %q: a failed label lookup must not disturb the resolution text", i, it.Detail, ackDetail(in[i].Resolution))
		}
	}
	// Even on the failure path a repeated id is attempted once, so a degraded
	// core is not hammered once per row.
	if got := core.callsFor(vA); got != 1 {
		t.Errorf("GetPolicyVersion(%s) called %d times on the failure path, want 1", vA, got)
	}
}

// TestAckPreviewItems_UnknownVersionFallsBackToUUID covers a lookup that
// succeeds but resolves to nothing (version purged, or core returns an empty
// message). Same contract as an error: fall back, never blank.
func TestAckPreviewItems_UnknownVersionFallsBackToUUID(t *testing.T) {
	const versionID = "cccccccc-0000-4000-8000-000000000003"
	core := &labelFakeCore{versions: map[string]PolicyVersionRef{}}
	items := labelOrchestrator(core).ackPreviewItems(context.Background(),
		[]AckItem{{PolicyVersionID: versionID, Resolution: "moved"}})

	if len(items) != 1 {
		t.Fatalf("got %d preview rows, want 1", len(items))
	}
	if want := "Policy version " + versionID; items[0].Label != want {
		t.Errorf("Label = %q, want the UUID fallback %q", items[0].Label, want)
	}
}

// TestAckPreviewItems_NoCoreClientStillRendersRows guards the nil-core case.
// Preview fails closed on a nil core today, but the row builder must not panic
// if that ever changes — a label is not worth a crash mid-review.
func TestAckPreviewItems_NoCoreClientStillRendersRows(t *testing.T) {
	const versionID = "dddddddd-0000-4000-8000-000000000004"
	items := labelOrchestrator(nil).ackPreviewItems(context.Background(),
		[]AckItem{{PolicyVersionID: versionID, Resolution: "moved"}})

	if len(items) != 1 {
		t.Fatalf("got %d preview rows, want 1", len(items))
	}
	if want := "Policy version " + versionID; items[0].Label != want {
		t.Errorf("Label = %q, want the UUID fallback %q", items[0].Label, want)
	}
}

// TestAckPreviewItems_MissingVersionNoOmitsSuffix keeps the label readable when
// core reports no version number rather than emitting a meaningless "(v0)".
func TestAckPreviewItems_MissingVersionNoOmitsSuffix(t *testing.T) {
	const versionID = "eeeeeeee-0000-4000-8000-000000000005"
	core := &labelFakeCore{versions: map[string]PolicyVersionRef{
		versionID: {ID: versionID, PolicyNumber: "POL-ENG-000012", PolicyTitle: "Acceptable Use Policy"},
	}}
	items := labelOrchestrator(core).ackPreviewItems(context.Background(),
		[]AckItem{{PolicyVersionID: versionID, Resolution: "moved"}})

	const want = "POL-ENG-000012 — Acceptable Use Policy"
	if items[0].Label != want {
		t.Errorf("Label = %q, want %q", items[0].Label, want)
	}
}
