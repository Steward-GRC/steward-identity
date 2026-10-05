// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package store holds the identity service's Postgres queries: users,
// groups, memberships, roles, second factors, SSO connections and merges.
//
// Methods return ready-to-marshal structs and take the optional inputs (NULL
// parent ids, granted_by) directly so handlers stay declarative. Every
// change and its audit event are written in one transaction: the event goes
// to the go-outbox table and exists only if the change commits.
package store

import (
	"time"

	"github.com/google/uuid"
)

// User mirrors policy.identity.v1.User plus internal fields the proto
// doesn't expose (timestamps, fcm_token before the read is wired through).
type User struct {
	ID              uuid.UUID
	ExternalSubject string
	Username        string // login username; for SSO/JIT users derived from the email local-part
	Email           string
	Name            string
	// FirstName/LastName are the structured given/family name. They are
	// populated from the IdP given_name/family_name claims on JIT (or set by the
	// user on /welcome); either may be empty when the IdP provided none. `Name`
	// remains the canonical display name.
	FirstName string
	LastName  string
	// Timezone is the user's IANA timezone name (e.g. "America/New_York"); empty
	// = unset. Consumed by steward-obligations to resolve real quiet-hours / digest
	// windows (it falls back to UTC when empty). Locale is a BCP-47 tag (e.g.
	// "en-US"); empty = unset. Both are self-service editable via UpdateMyProfile.
	Timezone string
	Locale   string
	// OnboardingComplete is false until the user finishes first-run
	// onboarding. The API exposes the negation as needs_onboarding.
	OnboardingComplete bool
	FCMToken           string
	Enabled            bool
	IsRoot             bool         // the protected root site-admin; at most one exists
	LocalAccount       bool         // has a local password, managed in Steward rather than by an identity provider
	Roles              []string     // global roles only (scope_category='')
	ScopedRoles        []ScopedRole // author/approver with their category
	Groups             []uuid.UUID  // directory (platform) group memberships
	Memberships        []Membership // per-group membership provenance, parallel to Groups
	ManagedGroups      []uuid.UUID  // groups this user is a LOCAL group-manager of
	IdpGroups          []string
	PolicyOverrides    []PolicyOverride
	ReadSensitive      bool // individual policy.read_sensitive grant (root-only to assign)
	CreatedAt          time.Time
	UpdatedAt          time.Time
	// DeletedAt is the soft-delete (tombstone) stamp; nil for a live account.
	// A tombstoned row is kept only so historical audit, acknowledgement and
	// approval records still resolve to a name; it is not a usable account.
	// The resolve paths (GetUser, GetUserByEmail, GetUserByUsername,
	// GetUserByExternalSubject) still return tombstoned rows, so callers can
	// show a closed account as closed.
	DeletedAt *time.Time
	// MergedIntoUserID is the SURVIVING account a tombstoned row was merged into
	// by MergeAccounts; nil when the account was deleted outright, and always
	// nil for a live account. It is the trail from "where did this person's
	// records go" to the account that holds them now.
	MergedIntoUserID *uuid.UUID
}

// Tombstoned reports whether the row is a soft-deleted (deleted or merged-away)
// account. Prefer this over Enabled==false: a DISABLED account with
// DeletedAt==nil is a live account and the canonical account-merge SOURCE.
func (u User) Tombstoned() bool { return u.DeletedAt != nil }

// ScopedRole is a role paired with its policy category (e.g. author/Facilities).
type ScopedRole struct {
	Role     string
	Category string
}

// PolicyOverride holds a per-user allow/deny override for a specific policy number.
type PolicyOverride struct {
	PolicyNumber string
	Effect       string // "allow" | "deny"
}

// Membership is one group membership with its provenance.
// GroupID matches an entry in User.Groups; Source is "manual" (admin /
// self-service / group-manager grant) or "idp-sync" (created by the IdP
// group-mapping path). It lets callers render IdP-synced memberships read-only
// and lets the store refuse a group-manager's edit of a sync-owned row.
type Membership struct {
	GroupID uuid.UUID
	Source  string // "manual" | "idp-sync"
}

// Group mirrors policy.identity.v1.Group.
type Group struct {
	ID        uuid.UUID
	Name      string
	ParentID  uuid.UUID // uuid.Nil = root
	Metadata  map[string]string
	CreatedAt time.Time
	UpdatedAt time.Time
}
