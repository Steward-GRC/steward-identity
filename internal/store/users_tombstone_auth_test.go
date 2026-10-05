// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// Tombstone-blind account adoption and lookup paths.
//
// User search filters `AND deleted_at IS NULL` to user SEARCH. The other
// user-resolving queries were tombstone-blind, and each was safe only
// INCIDENTALLY: both tombstone writers (DeleteUser, TombstoneMergedSource) also
// set `enabled = false`, and the downstream checks reject a disabled account.
//
// Every test below therefore RE-ENABLES the tombstoned row after tombstoning it
// (`enabled = true, deleted_at IS NOT NULL`) — a state no production path
// creates today, EXCEPT TransferRoot, which unconditionally sets
// `enabled = true` on its target. Re-enabling is what makes these assertions
// bite for the right reason: a test against an `enabled = false` tombstone
// passes on the OLD code too, proving nothing about the deleted_at filter.
//
// The deliberate NON-changes are pinned by
// TestResolvePathsStayTombstoneBlind and by the pre-existing
// TestGetUserStillReturnsTombstonedUser in users_search_tombstone_test.go.

// tombstone soft-deletes userID the way DeleteUser does and then re-enables the
// row, isolating `deleted_at` as the only thing a query can key on.
func tombstoneAndReEnable(t *testing.T, pool *pgxpool.Pool, s *store.Store, userID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.DeleteUser(ctx, userID, nil, "test"); err != nil {
		t.Fatalf("DeleteUser %s: %v", userID, err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET enabled = true WHERE id = $1`, userID); err != nil {
		t.Fatalf("re-enable tombstoned user %s: %v", userID, err)
	}
	var deletedAtSet, enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT deleted_at IS NOT NULL, enabled FROM users WHERE id = $1`, userID,
	).Scan(&deletedAtSet, &enabled); err != nil {
		t.Fatalf("verify tombstone shape %s: %v", userID, err)
	}
	if !deletedAtSet || !enabled {
		t.Fatalf("fixture is not an enabled tombstone: deleted_at set=%v enabled=%v", deletedAtSet, enabled)
	}
}

// mergeTombstoneAndReEnable produces the TombstoneMergedSource shape (deleted_at
// + merged_into_user_id) and re-enables the row, for the same reason.
func mergeTombstoneAndReEnable(t *testing.T, pool *pgxpool.Pool, sourceID, targetID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE users
		    SET deleted_at = now(), merged_into_user_id = $2, enabled = true
		  WHERE id = $1`, sourceID, targetID); err != nil {
		t.Fatalf("merge-tombstone %s: %v", sourceID, err)
	}
}

// TestFindAdoptableLocalUserSkipsTombstoned is the headline defect: a federated
// login must never ADOPT a merged-away or deleted local row. A tombstoned local
// account keeps its email, username and empty external_subject, so it still
// matched findAdoptableByField's WHERE and an SSO login could be pointed at a
// record whose data now belongs to a different user.
func TestFindAdoptableLocalUserSkipsTombstoned(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	live, err := s.PreCreateLocalUser(ctx, "adoptlive", "live@adopt.example.org", "Live Adoptable")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	dead, err := s.PreCreateLocalUser(ctx, "adoptdead", "dead@adopt.example.org", "Deleted Adoptable")
	if err != nil {
		t.Fatalf("PreCreateLocalUser dead: %v", err)
	}
	merged, err := s.PreCreateLocalUser(ctx, "adoptmerged", "merged@adopt.example.org", "Merged Adoptable")
	if err != nil {
		t.Fatalf("PreCreateLocalUser merged: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)
	mergeTombstoneAndReEnable(t, pool, merged.ID, live.ID)

	// Control: the live pre-created row is still adoptable by BOTH hints, so a
	// failure below comes from the tombstone filter.
	if u, found, err := s.FindAdoptableLocalUser(ctx, "live@adopt.example.org", ""); err != nil || !found || u.ID != live.ID {
		t.Fatalf("control: live account must be adoptable by email: found=%v err=%v", found, err)
	}
	if u, found, err := s.FindAdoptableLocalUser(ctx, "", "adoptlive"); err != nil || !found || u.ID != live.ID {
		t.Fatalf("control: live account must be adoptable by username: found=%v err=%v", found, err)
	}

	for _, tc := range []struct{ name, email, username string }{
		{"soft-deleted by email", "dead@adopt.example.org", ""},
		{"soft-deleted by username", "", "adoptdead"},
		{"merged-away by email", "merged@adopt.example.org", ""},
		{"merged-away by username", "", "adoptmerged"},
	} {
		u, found, err := s.FindAdoptableLocalUser(ctx, tc.email, tc.username)
		if err != nil {
			t.Fatalf("%s: FindAdoptableLocalUser: %v", tc.name, err)
		}
		if found {
			t.Errorf("%s: a tombstoned local account must NOT be adoptable, got %s (%s)", tc.name, u.ID, u.Email)
		}
	}
}

// TestFindAdoptableLocalUserPrefersLiveOverTombstonedDuplicate covers the
// realistic prod shape: the same person has a tombstoned old row and a live
// pre-created row. The adoption must land on the live one, not on whichever row
// Postgres happens to return first.
func TestFindAdoptableLocalUserPrefersLiveOverTombstonedDuplicate(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	// The tombstoned row is created FIRST so any created_at tie-break would
	// wrongly prefer it.
	old, err := s.PreCreateLocalUser(ctx, "dupold", "dup@adopt.example.org", "Old Row")
	if err != nil {
		t.Fatalf("PreCreateLocalUser old: %v", err)
	}
	fresh, err := s.PreCreateLocalUser(ctx, "dupfresh", "dup@adopt.example.org", "Fresh Row")
	if err != nil {
		t.Fatalf("PreCreateLocalUser fresh: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, old.ID)

	u, found, err := s.FindAdoptableLocalUser(ctx, "dup@adopt.example.org", "")
	if err != nil {
		t.Fatalf("FindAdoptableLocalUser: %v", err)
	}
	if !found {
		t.Fatalf("the LIVE duplicate must still be adoptable")
	}
	if u.ID != fresh.ID {
		t.Errorf("adoption landed on the tombstoned duplicate %s, want live %s", u.ID, fresh.ID)
	}
}

// TestGetLocalUserByEmailSkipsTombstoned pins the OTP / local-credential
// lookup. It resolves the principal a password-reset or login-2FA code is
// minted for and verified against, so a tombstoned row here means an emailed
// OTP for a deleted account.
func TestGetLocalUserByEmailSkipsTombstoned(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	live, err := s.PreCreateLocalUser(ctx, "otplive", "live@otp.example.org", "Live Local")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	dead, err := s.PreCreateLocalUser(ctx, "otpdead", "dead@otp.example.org", "Dead Local")
	if err != nil {
		t.Fatalf("PreCreateLocalUser dead: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)

	if u, err := s.GetLocalUserByEmail(ctx, "live@otp.example.org"); err != nil || u.ID != live.ID {
		t.Fatalf("control: live local account must resolve: %v", err)
	}
	if u, err := s.GetLocalUserByEmail(ctx, "dead@otp.example.org"); err == nil {
		t.Errorf("a tombstoned local account must not be an OTP target, got %s", u.ID)
	} else if err != store.ErrNotFound {
		t.Errorf("want ErrNotFound for a tombstoned local account, got %v", err)
	}
}

// TestGetLocalUserByEmailPrefersLiveOverTombstonedDuplicate is the
// `ORDER BY created_at ASC LIMIT 1` trap: the OLDEST row wins the tie-break, and
// the tombstone is usually the older one, so a duplicate-email pair would have
// resolved the OTP onto the deleted account.
func TestGetLocalUserByEmailPrefersLiveOverTombstonedDuplicate(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	old, err := s.PreCreateLocalUser(ctx, "otpold", "dup@otp.example.org", "Old Local")
	if err != nil {
		t.Fatalf("PreCreateLocalUser old: %v", err)
	}
	fresh, err := s.PreCreateLocalUser(ctx, "otpfresh", "dup@otp.example.org", "Fresh Local")
	if err != nil {
		t.Fatalf("PreCreateLocalUser fresh: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, old.ID)

	u, err := s.GetLocalUserByEmail(ctx, "dup@otp.example.org")
	if err != nil {
		t.Fatalf("GetLocalUserByEmail: %v", err)
	}
	if u.ID != fresh.ID {
		t.Errorf("OTP lookup resolved the tombstoned duplicate %s, want live %s", u.ID, fresh.ID)
	}
}

// TestBreakGlassLoginEligibleSkipsTombstoned pins the break-glass eligibility
// lookup. A tombstoned privileged local account reported eligible=true/"ok",
// which is the one path where a wrong answer hands out an audited login that
// bypasses the IdP.
func TestBreakGlassLoginEligibleSkipsTombstoned(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	live, err := s.PreCreateLocalUser(ctx, "bglive", "live@bg.example.org", "Live Site Admin")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	dead, err := s.PreCreateLocalUser(ctx, "bgdead", "dead@bg.example.org", "Dead Site Admin")
	if err != nil {
		t.Fatalf("PreCreateLocalUser dead: %v", err)
	}
	for _, id := range []uuid.UUID{live.ID, dead.ID} {
		if _, err := s.GrantRole(ctx, id, "site-admin", "", nil, "test"); err != nil {
			t.Fatalf("GrantRole site-admin %s: %v", id, err)
		}
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)

	for _, ident := range []string{"live@bg.example.org", "bglive"} {
		ok, reason, err := s.BreakGlassLoginEligible(ctx, ident)
		if err != nil {
			t.Fatalf("control BreakGlassLoginEligible(%q): %v", ident, err)
		}
		if !ok || reason != "ok" {
			t.Fatalf("control: live privileged local account must be eligible, got ok=%v reason=%q", ok, reason)
		}
	}
	for _, ident := range []string{"dead@bg.example.org", "bgdead"} {
		ok, reason, err := s.BreakGlassLoginEligible(ctx, ident)
		if err != nil {
			t.Fatalf("BreakGlassLoginEligible(%q): %v", ident, err)
		}
		if ok {
			t.Errorf("a tombstoned privileged account must NOT be break-glass eligible (%q, reason %q)", ident, reason)
		}
		if reason != "unknown_user" {
			t.Errorf("want reason %q for a tombstoned account, got %q", "unknown_user", reason)
		}
	}
	_ = live
}

// TestBreakGlassLoginEligibleResolvesLiveRowWhenTombstoneShadowsIt covers the
// missing LIMIT 1 on the eligibility query: with a tombstoned duplicate AND a
// live row on the same email, QueryRow silently took whichever row Postgres
// returned first, so eligibility was nondeterministic.
func TestBreakGlassLoginEligibleResolvesLiveRowWhenTombstoneShadowsIt(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	old, err := s.PreCreateLocalUser(ctx, "bgold", "dup@bg.example.org", "Old Row")
	if err != nil {
		t.Fatalf("PreCreateLocalUser old: %v", err)
	}
	fresh, err := s.PreCreateLocalUser(ctx, "bgfresh", "dup@bg.example.org", "Fresh Row")
	if err != nil {
		t.Fatalf("PreCreateLocalUser fresh: %v", err)
	}
	// Only the LIVE row is privileged. If the tombstone is picked, eligibility
	// wrongly reports not_privileged and a real site-admin is locked out.
	if _, err := s.GrantRole(ctx, fresh.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, old.ID)

	ok, reason, err := s.BreakGlassLoginEligible(ctx, "dup@bg.example.org")
	if err != nil {
		t.Fatalf("BreakGlassLoginEligible: %v", err)
	}
	if !ok || reason != "ok" {
		t.Errorf("the LIVE privileged row must win over a tombstoned duplicate, got ok=%v reason=%q", ok, reason)
	}
}

// TestJITProvisionByEmailDoesNotReuseTombstoned covers the by-email JIT path
// END TO END. Fixing only the in-lock recheck would have been ineffective: the
// FAST PATH calls GetUserByEmail, which is deliberately tombstone-blind, so the
// tombstone was returned before the recheck was ever reached — and because that
// lookup is `ORDER BY created_at ASC`, the OLDER tombstone was actively
// PREFERRED over a newer live row.
func TestJITProvisionByEmailDoesNotReuseTombstoned(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	dead, err := s.PreCreateLocalUser(ctx, "jitdead", "person@jit.example.org", "Deleted Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)

	u, created, err := s.JITProvisionByEmail(ctx, "person@jit.example.org", "New", "Person")
	if err != nil {
		t.Fatalf("JITProvisionByEmail: %v", err)
	}
	if u.ID == dead.ID {
		t.Fatalf("JIT-by-email resolved the TOMBSTONED row %s — a federated login was pointed at a deleted account", dead.ID)
	}
	if !created {
		t.Errorf("a fresh federated row should have been created (created=false means an existing row was reused)")
	}

	// Control: a SECOND call is idempotent on the live row it just made — the
	// filter must not turn JIT-by-email into an insert-every-time loop.
	again, createdAgain, err := s.JITProvisionByEmail(ctx, "person@jit.example.org", "New", "Person")
	if err != nil {
		t.Fatalf("JITProvisionByEmail second call: %v", err)
	}
	if createdAgain {
		t.Errorf("second JITProvisionByEmail must be idempotent, but created another row")
	}
	if again.ID != u.ID {
		t.Errorf("second call resolved %s, want the row created first %s", again.ID, u.ID)
	}
}

// TestListAllUsersAndCountAllUsersExcludeTombstonedExplicitly pins the
// "Everyone" ack audience. These two filter `enabled = true`, which excluded
// tombstones only because tombstoning happens to disable the row. The fixture
// re-enables the tombstone, so this test FAILS on the old code and proves the
// exclusion is now an explicit predicate.
func TestListAllUsersAndCountAllUsersExcludeTombstonedExplicitly(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	baseCount, err := s.CountAllUsers(ctx)
	if err != nil {
		t.Fatalf("CountAllUsers baseline: %v", err)
	}
	live, err := s.PreCreateLocalUser(ctx, "audlive", "live@aud.example.org", "Live Audience")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	dead, err := s.PreCreateLocalUser(ctx, "auddead", "dead@aud.example.org", "Dead Audience")
	if err != nil {
		t.Fatalf("PreCreateLocalUser dead: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)

	all, err := s.ListAllUsers(ctx)
	if err != nil {
		t.Fatalf("ListAllUsers: %v", err)
	}
	if !containsUser(all, live.ID) {
		t.Errorf("control: live user missing from the Everyone audience (got %d)", len(all))
	}
	if containsUser(all, dead.ID) {
		t.Errorf("a re-enabled tombstone leaked into the Everyone audience — the exclusion is still riding on enabled=false")
	}
	n, err := s.CountAllUsers(ctx)
	if err != nil {
		t.Fatalf("CountAllUsers: %v", err)
	}
	if n != baseCount+1 {
		t.Errorf("CountAllUsers = %d, want %d (baseline + the one live user)", n, baseCount+1)
	}
	if n != len(all) {
		t.Errorf("CountAllUsers (%d) disagrees with len(ListAllUsers) (%d)", n, len(all))
	}
}

// TestBootstrapAdminSkipsTombstonedAdmin pins the first-run bootstrap: it
// reports "an admin already exists" and hands back whichever site-admin row it
// finds. A tombstoned admin was reported as the live admin, so a cluster whose
// only admin had been deleted looked provisioned while being unadministrable.
func TestBootstrapAdminSkipsTombstonedAdmin(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	dead, err := s.PreCreateLocalUser(ctx, "bsdead", "dead@bs.example.org", "Deleted Admin")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	if _, err := s.GrantRole(ctx, dead.ID, "site-admin", "", nil, "test"); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)
	// DeleteUser also DELETEs user_roles, which is the *only* reason this query
	// was safe before the deleted_at filter: with the role row gone the EXISTS probe was
	// false. Re-insert it so the assertion tests the deleted_at predicate rather
	// than the access-row cleanup, which is what the issue means by "safe only
	// incidentally". A tombstone created by direct SQL, or by a future tombstone
	// variant that skips the cleanup, is exactly this shape.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role, scope_category) VALUES ($1, 'site-admin', '')
		   ON CONFLICT DO NOTHING`, dead.ID); err != nil {
		t.Fatalf("re-insert site-admin role on tombstone: %v", err)
	}

	u, created, err := s.BootstrapAdmin(ctx, "bs-subject", "fresh@bs.example.org", "test")
	if err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	if u.ID == dead.ID {
		t.Fatalf("BootstrapAdmin returned the TOMBSTONED admin %s as the existing admin", dead.ID)
	}
	if !created {
		t.Errorf("with only a tombstoned admin present, BootstrapAdmin must create a real one (created=false)")
	}

	// Control: it is still idempotent once a LIVE admin exists.
	again, createdAgain, err := s.BootstrapAdmin(ctx, "bs-subject", "fresh@bs.example.org", "test")
	if err != nil {
		t.Fatalf("BootstrapAdmin second call: %v", err)
	}
	if createdAgain {
		t.Errorf("control: BootstrapAdmin must be idempotent with a live admin present")
	}
	if again.ID != u.ID {
		t.Errorf("control: second BootstrapAdmin resolved %s, want %s", again.ID, u.ID)
	}
}

// TestTransferRootRefusesTombstonedTarget is the concrete instance of the
// issue's hypothetical "if any future path re-enables an account". TransferRoot
// already does: it sets `enabled = true` on its target. Transferring root onto a
// tombstoned row would therefore MANUFACTURE the enabled tombstone that every
// other query's safety currently rests on not existing — and make the protected
// root account a deleted one.
func TestTransferRootRefusesTombstonedTarget(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	root, err := s.PreCreateLocalUserRoot(ctx, "trroot", "root@tr.example.org", "Root")
	if err != nil {
		t.Fatalf("PreCreateLocalUserRoot: %v", err)
	}
	dead, err := s.PreCreateLocalUser(ctx, "trdead", "dead@tr.example.org", "Deleted Target")
	if err != nil {
		t.Fatalf("PreCreateLocalUser dead: %v", err)
	}
	live, err := s.PreCreateLocalUser(ctx, "trlive", "live@tr.example.org", "Live Target")
	if err != nil {
		t.Fatalf("PreCreateLocalUser live: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)

	if _, err := s.TransferRoot(ctx, dead.ID, nil, "test"); err == nil {
		t.Errorf("TransferRoot onto a tombstoned account must be refused")
	} else if err != store.ErrNotFound {
		t.Errorf("want ErrNotFound transferring root onto a tombstone, got %v", err)
	}
	var stillRoot bool
	if err := pool.QueryRow(ctx, `SELECT is_root FROM users WHERE id = $1`, root.ID).Scan(&stillRoot); err != nil {
		t.Fatalf("re-read root: %v", err)
	}
	if !stillRoot {
		t.Errorf("a refused TransferRoot must leave the original root in place")
	}

	// Control: the transfer still works onto a live account.
	if _, err := s.TransferRoot(ctx, live.ID, nil, "test"); err != nil {
		t.Fatalf("control: TransferRoot onto a live account: %v", err)
	}
}

// TestResolvePathsStayTombstoneBlind pins the deliberate NON-changes of the
// deleted_at filters, so a later sweep does not "fix" them:
//
//   - GetUser / GetUserByEmail / GetUserByUsername back resolveUserLabels;
//     filtering them would print raw UUIDs across every historical audit,
//     acknowledgment and approval row authored by a merged-away user
//
// . Also pinned by TestGetUserStillReturnsTombstonedUser.
//   - GetUserByExternalSubject is the ResolveClaims lookup, and ErrNotFound
//     there is NOT a denial — it falls through to adopt-or-JIT-provision, whose
//     insert is `ON CONFLICT (external_subject) DO UPDATE`. Filtering it would
//     therefore RESURRECT the tombstoned row on the deleted user's next login
//     instead of refusing it. Tombstone enforcement for that path belongs at the
//     session/enabled gate, not in this query.
//   - nextAvailableUsername probes users_lower_username_uniq, which a tombstoned
//     row still occupies, so it MUST see tombstones or PreCreateLocalUser would
//     pick a name the index then rejects with a raw 23505.
func TestResolvePathsStayTombstoneBlind(t *testing.T) {
	pool := newTestDB(t)
	if pool == nil {
		return
	}
	s := newStoreFor(t, pool)
	ctx := context.Background()

	dead, err := s.PreCreateLocalUser(ctx, "resolvedead", "dead@resolve2.example.org", "Deleted Person")
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	subject := "resolve-subject-" + dead.ID.String()
	if _, err := pool.Exec(ctx, `UPDATE users SET external_subject = $2 WHERE id = $1`, dead.ID, subject); err != nil {
		t.Fatalf("set subject: %v", err)
	}
	tombstoneAndReEnable(t, pool, s, dead.ID)

	if u, err := s.GetUser(ctx, dead.ID); err != nil || u.ID != dead.ID {
		t.Errorf("GetUser must still resolve a tombstoned user for audit labels: %v", err)
	}
	if u, err := s.GetUserByEmail(ctx, "dead@resolve2.example.org"); err != nil || u.ID != dead.ID {
		t.Errorf("GetUserByEmail must stay tombstone-blind (resolve path): %v", err)
	}
	if u, err := s.GetUserByUsername(ctx, "resolvedead"); err != nil || u.ID != dead.ID {
		t.Errorf("GetUserByUsername must stay tombstone-blind (resolve path): %v", err)
	}
	if u, err := s.GetUserByExternalSubject(ctx, subject); err != nil || u.ID != dead.ID {
		t.Errorf("GetUserByExternalSubject must stay tombstone-blind (filtering it resurrects the row via JIT): %v", err)
	}

	// The tombstoned row still owns its username in the unique index, so a
	// re-create of the same name must be refused rather than silently collide.
	if _, err := s.PreCreateLocalUser(ctx, "resolvedead", "other@resolve2.example.org", "Someone Else"); err == nil {
		t.Errorf("a tombstoned row still occupies users_lower_username_uniq; re-creating its username must conflict")
	}
}
