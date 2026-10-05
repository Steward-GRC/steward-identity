// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	outbox "github.com/Bugs5382/go-outbox"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// newTestStore returns a Store on a fresh, migrated database for the
// calling test, on DATABASE_TEST_DSN when it is set, otherwise on one
// throwaway testcontainers Postgres shared by the test binary.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	base := os.Getenv("DATABASE_TEST_DSN")
	if base == "" {
		base = sharedContainer(t)
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	defer admin.Close()
	var b [6]byte
	_, _ = rand.Read(b[:])
	dbName := "test_h_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, dbName)); err != nil {
		t.Fatalf("create db: %v", err)
	}
	u, _ := url.Parse(base)
	u.Path = "/" + dbName
	testDSN := u.String()
	t.Cleanup(func() {
		dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		drop, err := pgxpool.New(dctx, base)
		if err != nil {
			return
		}
		defer drop.Close()
		_, _ = drop.Exec(dctx, fmt.Sprintf(`DROP DATABASE %q WITH (FORCE)`, dbName))
	})

	migrationsDir, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if err := postgres.Migrate(testDSN, migrationsDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := postgres.New(ctx, testDSN)
	if err != nil {
		t.Fatalf("postgres.New: %v", err)
	}
	t.Cleanup(db.Close)
	ob, err := outbox.New(outbox.WithTable(store.AuditTable))
	if err != nil {
		t.Fatalf("outbox: %v", err)
	}
	if err := ob.Migrate(ctx, db); err != nil {
		t.Fatalf("outbox migrate: %v", err)
	}
	return store.New(db, ob)
}

var (
	containerOnce sync.Once
	containerDSN  string
	containerErr  error
)

func sharedContainer(t *testing.T) string {
	t.Helper()
	containerOnce.Do(func() {
		ctx := context.Background()
		c, err := tcpostgres.Run(ctx, "postgres:16",
			tcpostgres.WithDatabase("identity_test"),
			tcpostgres.WithUsername("test"),
			tcpostgres.WithPassword("test"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(60*time.Second),
			),
		)
		if err != nil {
			containerErr = err
			return
		}
		containerDSN, containerErr = c.ConnectionString(ctx, "sslmode=disable")
	})
	if containerErr != nil {
		t.Fatalf("start postgres container: %v", containerErr)
	}
	return containerDSN
}

func TestReadResolveClaimsJIT(t *testing.T) {
	s := newTestStore(t)
	h := hinted(handlers.NewReadHandler(s))
	// JIT-provisioning requires at least one identifying claim (a legitimate
	// sign-in always forwards an email or preferred_username). Provide
	// an email hint so the JIT path is exercised — a bare subject with no
	// claims is rejected by the anti-rogue-user guard (see
	// TestReadResolveClaimsNoIdentifyingClaims).
	jitCtx := incomingMDCtx(context.Background(), map[string]string{
		"x-identity-email": "sub-rh-1@corp.example.com",
	})
	resp, err := h.ResolveClaims(jitCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-rh-1"})
	if err != nil {
		t.Fatalf("ResolveClaims: %v", err)
	}
	if resp.User == nil {
		t.Fatal("nil user")
	}
	// Viewer access is implicit (not stored); a freshly JIT-provisioned user
	// has no stored roles.
	if len(resp.User.Roles) != 0 {
		t.Fatalf("expected no stored roles for new JIT user, got %v", resp.User.Roles)
	}
	// Second call hits the existing-user path (GetUserByExternalSubject).
	resp2, err := h.ResolveClaims(context.Background(), &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-rh-1"}) //nolint:staticcheck
	if err != nil {
		t.Fatalf("ResolveClaims (2): %v", err)
	}
	if resp2.User.Id != resp.User.Id {
		t.Fatalf("expected same user id; got %s vs %s", resp2.User.Id, resp.User.Id)
	}
}

// TestReadResolveClaimsJITPopulatesFirstLast verifies the gateway-forwarded
// given/family name hints (x-identity-first-name / x-identity-last-name) land
// on the JIT-provisioned row, and that `name` is composed from them when no
// display-name hint was forwarded.
func TestReadResolveClaimsJITPopulatesFirstLast(t *testing.T) {
	s := newTestStore(t)
	h := hinted(handlers.NewReadHandler(s))
	jitCtx := incomingMDCtx(context.Background(), map[string]string{
		"x-identity-email":      "mj@corp.example.com",
		"x-identity-first-name": "Mary",
		"x-identity-last-name":  "Jane",
	})
	resp, err := h.ResolveClaims(jitCtx, &identityv1.ResolveClaimsRequest{ExternalSubject: "sub-firstlast"})
	if err != nil {
		t.Fatalf("ResolveClaims: %v", err)
	}
	if resp.User.GetFirstName() != "Mary" || resp.User.GetLastName() != "Jane" {
		t.Fatalf("first/last: got %q/%q", resp.User.GetFirstName(), resp.User.GetLastName())
	}
	if resp.User.GetName() != "Mary Jane" {
		t.Fatalf("composed name: got %q want %q", resp.User.GetName(), "Mary Jane")
	}
}

// TestReadResolveClaimsNoIdentifyingClaims is the anti-rogue-user guard test:
// a ResolveClaims call carrying only a external_subject (no email, no
// preferred_username, no name) — as happens when a caller mistakenly passes a
// platform row id instead of a real external subject — must NOT create a
// blank user row. It must return an error and leave the user count unchanged.
func TestReadResolveClaimsNoIdentifyingClaims(t *testing.T) {
	s := newTestStore(t)
	h := hinted(handlers.NewReadHandler(s))

	before, err := s.ListUsersByEmail(context.Background(), "", 200, "", uuidNil())
	if err != nil {
		t.Fatalf("count users before: %v", err)
	}

	// Subject-only request: no email/preferred_username/name anywhere.
	_, err = h.ResolveClaims(context.Background(), &identityv1.ResolveClaimsRequest{
		ExternalSubject: "not-a-real-kc-subject-just-a-row-id",
	})
	if err == nil {
		t.Fatal("expected error for subject with no identifying claims, got nil (a blank rogue user may have been created)")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}

	after, err := s.ListUsersByEmail(context.Background(), "", 200, "", uuidNil())
	if err != nil {
		t.Fatalf("count users after: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("user count changed: before=%d after=%d (a rogue user was created)", len(before), len(after))
	}
}

func TestReadResolveClaimsMissingSub(t *testing.T) {
	s := newTestStore(t)
	h := hinted(handlers.NewReadHandler(s))
	_, err := h.ResolveClaims(context.Background(), &identityv1.ResolveClaimsRequest{})
	if err == nil {
		t.Fatal("expected error for missing external_subject")
	}
}

func TestReadResolveEmailNotFound(t *testing.T) {
	s := newTestStore(t)
	h := hinted(handlers.NewReadHandler(s))
	// Use a syntactically valid but unknown UUID.
	_, err := h.ResolveEmail(context.Background(), &identityv1.ResolveEmailRequest{UserId: "00000000-0000-0000-0000-000000000000"})
	if err == nil {
		t.Fatal("expected NotFound, got nil")
	}
}

func TestReadGetGroup(t *testing.T) {
	s := newTestStore(t)
	g, err := s.CreateGroup(context.Background(), "Test", uuidNil(), nil, nil, "tester")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	h := hinted(handlers.NewReadHandler(s))
	resp, err := h.GetGroup(context.Background(), &identityv1.GetGroupRequest{GroupId: g.ID.String()})
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if resp.Group.Name != "Test" {
		t.Fatalf("name: %q", resp.Group.Name)
	}
}

// TestReadResolveClaimsProjectsIdpGroups verifies that ResolveClaims returns
// IdpGroups that were seeded via store.ReplaceUserIdpGroups.
func TestReadResolveClaimsProjectsIdpGroups(t *testing.T) {
	s := newTestStore(t)
	// JIT-provision a user so we have an ID.
	u, err := s.JITProvision(context.Background(), "kc-adg-1", "adg1@e", "AdG1")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	// Seed identity provider groups for that user directly via the store.
	if err := s.ReplaceUserIdpGroups(context.Background(), u.ID, []string{"corp-vpn", "it-admin"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups: %v", err)
	}
	h := hinted(handlers.NewReadHandler(s))
	resp, err := h.ResolveClaims(context.Background(),
		&identityv1.ResolveClaimsRequest{ExternalSubject: "kc-adg-1"})
	if err != nil {
		t.Fatalf("ResolveClaims: %v", err)
	}
	idpGroups := resp.User.IdpGroups
	if len(idpGroups) != 2 {
		t.Fatalf("expected 2 idp_groups, got %d: %v", len(idpGroups), idpGroups)
	}
	found := map[string]bool{}
	for _, g := range idpGroups {
		found[g] = true
	}
	if !found["corp-vpn"] || !found["it-admin"] {
		t.Fatalf("expected corp-vpn and it-admin in idp_groups, got %v", idpGroups)
	}
}

// TestReadGetUserProjectsIdpGroups verifies that GetUser returns IdpGroups seeded
// via store.ReplaceUserIdpGroups.
func TestReadGetUserProjectsIdpGroups(t *testing.T) {
	s := newTestStore(t)
	u, err := s.JITProvision(context.Background(), "kc-adg-2", "adg2@e", "AdG2")
	if err != nil {
		t.Fatalf("JIT: %v", err)
	}
	if err := s.ReplaceUserIdpGroups(context.Background(), u.ID, []string{"helpdesk"}); err != nil {
		t.Fatalf("ReplaceUserIdpGroups: %v", err)
	}
	h := hinted(handlers.NewReadHandler(s))
	resp, err := h.GetUser(context.Background(),
		&identityv1.GetUserRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if len(resp.User.IdpGroups) != 1 || resp.User.IdpGroups[0] != "helpdesk" {
		t.Fatalf("expected IdpGroups=[helpdesk], got %v", resp.User.IdpGroups)
	}
}

// TestReadListUsersByEmail walks the empty-result / substring-match /
// pagination cursor paths. Table-driven over a handful of users.
func TestReadListUsersByEmail(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	emails := []string{
		"alice@dev.example.com",
		"alicia@dev.example.com",
		"bob@dev.example.com",
		"carol@other.example.com",
	}
	for i, e := range emails {
		if _, err := s.JITProvision(ctx, fmt.Sprintf("kc-luq-%d", i), e, "U"); err != nil {
			t.Fatalf("JITProvision %s: %v", e, err)
		}
	}
	h := hinted(handlers.NewReadHandler(s))

	// Empty-result substring.
	respEmpty, err := h.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: "nobody",
		Limit:          10,
	})
	if err != nil {
		t.Fatalf("ListUsersByEmail empty: %v", err)
	}
	if len(respEmpty.Users) != 0 {
		t.Fatalf("expected 0 results, got %d", len(respEmpty.Users))
	}
	if respEmpty.NextPageToken != "" {
		t.Fatalf("expected empty next_page_token on final page, got %q", respEmpty.NextPageToken)
	}

	// Substring match (case-insensitive) matches three "ali"/"bob" rows? "ali" only matches
	// alice + alicia.
	respAli, err := h.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: "Ali",
		Limit:          10,
	})
	if err != nil {
		t.Fatalf("ListUsersByEmail ali: %v", err)
	}
	if len(respAli.Users) != 2 {
		t.Fatalf("expected 2 'Ali' matches, got %d: %v", len(respAli.Users), respAli.Users)
	}
	// Sorted by email ASC.
	if respAli.Users[0].Email != "alice@dev.example.com" {
		t.Fatalf("expected alice first, got %q", respAli.Users[0].Email)
	}

	// Pagination boundary: limit=2 over the four-user set returns 2 + a non-empty cursor.
	respPage1, err := h.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: "",
		Limit:          2,
	})
	if err != nil {
		t.Fatalf("ListUsersByEmail page1: %v", err)
	}
	if len(respPage1.Users) != 2 {
		t.Fatalf("expected 2 users page 1, got %d", len(respPage1.Users))
	}
	if respPage1.NextPageToken == "" {
		t.Fatalf("expected non-empty next_page_token after full page")
	}

	respPage2, err := h.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: "",
		Limit:          2,
		PageToken:      respPage1.NextPageToken,
	})
	if err != nil {
		t.Fatalf("ListUsersByEmail page2: %v", err)
	}
	if len(respPage2.Users) == 0 {
		t.Fatalf("expected at least one user on page 2")
	}
	// Page 2 must not overlap with page 1.
	page1IDs := map[string]bool{}
	for _, u := range respPage1.Users {
		page1IDs[u.Id] = true
	}
	for _, u := range respPage2.Users {
		if page1IDs[u.Id] {
			t.Fatalf("page 2 overlapped page 1 on user %s", u.Id)
		}
	}

	// Invalid page_token surfaces InvalidArgument.
	_, err = h.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		PageToken: "!!!not-base64",
	})
	if err == nil {
		t.Fatal("expected error for invalid page_token")
	}
}

// TestReadListGroups walks the four shape variants (parent set?, descendants?)
// and the cursor + invalid-token edge cases. A small three-level tree is
// enough to disambiguate parent vs descendants.
func TestReadListGroups(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	root, _ := s.CreateGroup(ctx, "Org", uuidNil(), nil, nil, "t")
	eng, _ := s.CreateGroup(ctx, "Engineering", root.ID, nil, nil, "t")
	_, _ = s.CreateGroup(ctx, "Backend", eng.ID, nil, nil, "t")
	_, _ = s.CreateGroup(ctx, "Frontend", eng.ID, nil, nil, "t")
	_, _ = s.CreateGroup(ctx, "People", root.ID, nil, nil, "t")
	h := hinted(handlers.NewReadHandler(s))

	// Root-level groups only (parent_id="", descendants=false) → just "Org".
	respRoot, err := h.ListGroups(ctx, &identityv1.ListGroupsRequest{Limit: 10})
	if err != nil {
		t.Fatalf("ListGroups root: %v", err)
	}
	if len(respRoot.Groups) != 1 || respRoot.Groups[0].Name != "Org" {
		t.Fatalf("expected only 'Org' root group, got %v", respRoot.Groups)
	}

	// Whole tree (parent_id="", descendants=true) → 5 groups.
	respAll, err := h.ListGroups(ctx, &identityv1.ListGroupsRequest{
		IncludeDescendants: true,
		Limit:              10,
	})
	if err != nil {
		t.Fatalf("ListGroups all: %v", err)
	}
	if len(respAll.Groups) != 5 {
		t.Fatalf("expected 5 groups in whole tree, got %d", len(respAll.Groups))
	}

	// Direct children of root → "Engineering" + "People".
	respChildren, err := h.ListGroups(ctx, &identityv1.ListGroupsRequest{
		ParentId: root.ID.String(),
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("ListGroups direct children: %v", err)
	}
	if len(respChildren.Groups) != 2 {
		t.Fatalf("expected 2 direct children, got %d", len(respChildren.Groups))
	}

	// Descendants of root → "Engineering", "Backend", "Frontend", "People" (4, excludes root).
	respDesc, err := h.ListGroups(ctx, &identityv1.ListGroupsRequest{
		ParentId:           root.ID.String(),
		IncludeDescendants: true,
		Limit:              10,
	})
	if err != nil {
		t.Fatalf("ListGroups descendants: %v", err)
	}
	if len(respDesc.Groups) != 4 {
		t.Fatalf("expected 4 descendants, got %d", len(respDesc.Groups))
	}

	// Pagination boundary: limit=2 over the 5-group whole tree returns 2 + cursor.
	respPage1, err := h.ListGroups(ctx, &identityv1.ListGroupsRequest{
		IncludeDescendants: true,
		Limit:              2,
	})
	if err != nil {
		t.Fatalf("ListGroups page1: %v", err)
	}
	if len(respPage1.Groups) != 2 || respPage1.NextPageToken == "" {
		t.Fatalf("page1 boundary failed: groups=%d token=%q", len(respPage1.Groups), respPage1.NextPageToken)
	}

	respPage2, err := h.ListGroups(ctx, &identityv1.ListGroupsRequest{
		IncludeDescendants: true,
		Limit:              2,
		PageToken:          respPage1.NextPageToken,
	})
	if err != nil {
		t.Fatalf("ListGroups page2: %v", err)
	}
	if len(respPage2.Groups) == 0 {
		t.Fatalf("expected at least one group on page 2")
	}

	// Invalid page_token surfaces InvalidArgument.
	_, err = h.ListGroups(ctx, &identityv1.ListGroupsRequest{PageToken: "!!!not-base64"})
	if err == nil {
		t.Fatal("expected error for invalid page_token")
	}

	// Invalid parent_id (non-uuid string) surfaces InvalidArgument.
	_, err = h.ListGroups(ctx, &identityv1.ListGroupsRequest{ParentId: "not-a-uuid"})
	if err == nil {
		t.Fatal("expected error for invalid parent_id")
	}
}
