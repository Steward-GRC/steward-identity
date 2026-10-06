// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/safecast"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// listPageMaxLimit caps the per-page result count for the cursor-paged read
// RPCs (ListUsersByEmail / ListGroups). Tracks the audit-service convention
// (200 max, 50 default) so operator scripts can rely on a single cap across
// the platform.
const listPageMaxLimit = 200
const listPageDefaultLimit = 50

// ReadHandler serves IdentityReadService.
type ReadHandler struct {
	identityv1.UnimplementedIdentityReadServiceServer
	store *store.Store
	// signIn is the Kratos admin API: passwords and sessions. Nil turns those
	// calls into coded "unavailable" errors.
	signIn signInService
	// otp holds the email-code wiring (password reset and sign-in codes);
	// the code RPCs answer Unavailable while it is unset.
	otp *otpDeps
	// mfa holds the second-factor wiring (authenticator secrets and email
	// codes); the factor RPCs answer Unavailable while it is unset.
	mfa *mfaDeps
	// webauthn is the passkey relying party. Unset, the ceremonies answer
	// Unavailable; listing and removing credentials still work.
	webauthn *webauthn.WebAuthn
	// events publishes the SSO lifecycle events; nil skips them.
	events ssoEventPublisher
	// acctCreatedPub publishes account.created on every genuine account
	// create; nil skips it.
	acctCreatedPub accountCreatedPublisher
	// lastSeen throttles the session last-seen writes GetUser makes.
	lastSeen *seenThrottle
}

// WithSignIn wires the Kratos admin API.
func (h *ReadHandler) WithSignIn(k signInService) *ReadHandler {
	h.signIn = k
	return h
}

// WithAccountCreatedPublisher wires the account.created publisher.
func (h *ReadHandler) WithAccountCreatedPublisher(p accountCreatedPublisher) *ReadHandler {
	h.acctCreatedPub = p
	return h
}

// WithSSOEventPublisher wires the SSO lifecycle publisher.
func (h *ReadHandler) WithSSOEventPublisher(p ssoEventPublisher) *ReadHandler {
	h.events = p
	return h
}

// NewReadHandler returns an IdentityReadService on s.
func NewReadHandler(s *store.Store) *ReadHandler {
	return &ReadHandler{store: s, lastSeen: newSeenThrottle(DefaultLastSeenThrottle, time.Now)}
}

// ResolveClaims looks a user up by the sign-in service's subject and creates
// the account on first sight. A pre-created local account with the same
// email or username is adopted instead of duplicated. Claims only fill empty
// fields; a stored value is never overwritten.
func (h *ReadHandler) ResolveClaims(ctx context.Context, req *identityv1.ResolveClaimsRequest) (*identityv1.ResolveClaimsResponse, error) {
	subject := req.GetExternalSubject()
	if subject == "" {
		return nil, status.Error(codes.InvalidArgument, "external_subject required")
	}
	email, name := strings.TrimSpace(req.GetEmail()), strings.TrimSpace(req.GetName())
	firstName, lastName := strings.TrimSpace(req.GetFirstName()), strings.TrimSpace(req.GetLastName())
	preferredUsername := strings.TrimSpace(req.GetPreferredUsername())
	alias := strings.TrimSpace(req.GetConnectionAlias())

	u, err := h.store.GetUserByExternalSubject(ctx, subject)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, statusFromStoreErr(err)
	}
	if errors.Is(err, store.ErrNotFound) {
		jitCreated := false
		provision := func() error {
			if h.jitDisabledForConnAlias(ctx, alias) {
				return ssoJitDisabledError(ctx, subject)
			}
			if err := guardNoIdentifyingClaims(ctx, subject, email, preferredUsername, name, firstName, lastName); err != nil {
				return err
			}
			provisioned, err := h.store.JITProvisionWithNames(ctx, subject, email, name, firstName, lastName)
			if err != nil {
				return statusFromStoreErr(err)
			}
			u, jitCreated = provisioned, true
			return nil
		}
		adoptable, found, findErr := h.store.FindAdoptableLocalUser(ctx, email, preferredUsername)
		switch {
		case findErr != nil:
			return nil, statusFromStoreErr(findErr)
		case found:
			adoptErr := h.store.AdoptLocalUser(ctx, adoptable.ID, subject)
			if adoptErr != nil && !errors.Is(adoptErr, store.ErrConflict) {
				return nil, statusFromStoreErr(adoptErr)
			}
			// Won or lost the adoption race, the row now holding this subject
			// is the answer; if another subject won, provision a new row.
			adopted, lookupErr := h.store.GetUserByExternalSubject(ctx, subject)
			switch {
			case lookupErr == nil:
				u = adopted
			case errors.Is(lookupErr, store.ErrNotFound):
				if err := provision(); err != nil {
					return nil, err
				}
			default:
				return nil, statusFromStoreErr(lookupErr)
			}
		default:
			if err := provision(); err != nil {
				return nil, err
			}
		}
		if jitCreated {
			emitSSOEvent(ctx, h.events, eventSSOAccountProvisioned, map[string]any{
				"email":  u.Email,
				"userId": u.ID.String(),
			})
			emitAccountCreated(ctx, h.acctCreatedPub, u.ID.String())
		}
	} else if needsBackfill(u, email, name, firstName, lastName) {
		updated, err := h.backfill(ctx, u, email, name, firstName, lastName)
		if err != nil {
			return nil, err
		}
		u = updated
	}
	u, err = h.applyConnectionGroups(ctx, u, alias, req.GetIdpGroups())
	if err != nil {
		return nil, err
	}
	return &identityv1.ResolveClaimsResponse{User: userToProto(u)}, nil
}

func needsBackfill(u store.User, email, name, first, last string) bool {
	return (u.Email == "" && email != "") ||
		(u.FirstName == "" && first != "") ||
		(u.LastName == "" && last != "") ||
		(u.Name == "" && (name != "" || first != "" || last != ""))
}

// backfill fills only the empty fields. The display name is derived from the
// parts when either exists, else filled from the name claim.
func (h *ReadHandler) backfill(ctx context.Context, u store.User, email, name, first, last string) (store.User, error) {
	if u.Email == "" {
		u.Email = email
	}
	if u.FirstName == "" {
		u.FirstName = first
	}
	if u.LastName == "" {
		u.LastName = last
	}
	if u.FirstName != "" || u.LastName != "" {
		u.Name = strings.TrimSpace(u.FirstName + " " + u.LastName)
	} else if u.Name == "" {
		u.Name = name
	}
	updated, err := h.store.UpdateUserProfile(ctx, u.ID, u.Email, u.Name, u.FirstName, u.LastName, u.Timezone, u.Locale)
	if err != nil {
		return store.User{}, statusFromStoreErr(err)
	}
	return updated, nil
}

// applyConnectionGroups runs after an SSO sign-in (alias set): the asserted
// groups replace the user's identity provider groups, and the connection's
// group mappings add the mapped platform groups. A mapping failure never
// fails the sign-in; it is logged and the user keeps the groups they have.
func (h *ReadHandler) applyConnectionGroups(ctx context.Context, u store.User, alias string, groups []string) (store.User, error) {
	if alias == "" {
		return u, nil
	}
	clean := make([]string, 0, len(groups))
	for _, g := range groups {
		if g = strings.TrimSpace(g); g != "" {
			clean = append(clean, g)
		}
	}
	if err := h.store.ReplaceUserIdpGroups(ctx, u.ID, clean); err != nil {
		return store.User{}, statusFromStoreErr(err)
	}
	lg := logger.Ctx(ctx)
	if len(clean) > 0 {
		conn, connErr := h.store.GetIdPConnectionByAlias(ctx, alias)
		if connErr != nil {
			lg.Warn("idp group mapping: connection lookup failed, continuing without mapping", log.F("alias", alias), log.F("error", errText(connErr)))
		} else if applied, _, applyErr := h.store.ApplyIdPGroupMappings(ctx, u.ID, conn.ID, clean); applyErr != nil {
			lg.Warn("idp group mapping: apply failed, continuing", log.F("alias", alias), log.F("error", errText(applyErr)))
		} else if len(applied) > 0 {
			names := make([]string, 0, len(applied))
			for _, gid := range applied {
				if g, gerr := h.store.GetGroup(ctx, gid); gerr == nil {
					names = append(names, g.Name)
				} else {
					names = append(names, gid.String())
				}
			}
			emitSSOEvent(ctx, h.events, eventSSOAccessGranted, map[string]any{"email": u.Email, "groups": names})
		}
	}
	reloaded, err := h.store.GetUser(ctx, u.ID)
	if err != nil {
		lg.Warn("idp group mapping: re-hydrate user failed, continuing", log.F("alias", alias), log.F("error", errText(err)))
		return u, nil
	}
	return reloaded, nil
}

// GetUser returns a single user by platform id.
func (h *ReadHandler) GetUser(ctx context.Context, req *identityv1.GetUserRequest) (*identityv1.GetUserResponse, error) {
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	var sessionID uuid.UUID
	if req.GetSessionId() != "" {
		if sessionID, err = parseUUID(req.GetSessionId(), "session_id"); err != nil {
			return nil, err
		}
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if sessionID != uuid.Nil {
		h.touchSession(ctx, sessionID, u.ID)
	}
	return &identityv1.GetUserResponse{User: userToProto(u)}, nil
}

// GetUserByEmail resolves a single platform user by exact (case-insensitive)
// email match, across all accounts (local or federated) — unlike
// ListUsersByEmail's fuzzy substring search. Added for the gateway's Ory
// Kratos local-login backend: a pure
// lookup, no JIT provisioning. NotFound when no user matches.
func (h *ReadHandler) GetUserByEmail(ctx context.Context, req *identityv1.GetUserByEmailRequest) (*identityv1.GetUserByEmailResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	u, err := h.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.GetUserByEmailResponse{User: userToProto(u)}, nil
}

// JitProvisionByEmail finds a user by email and creates an SSO account when
// none exists. With just-in-time accounts off for the connection, only a
// live, pre-provisioned account may sign in. A fresh create emits the
// account-provisioned welcome; an existing user comes back unchanged.
func (h *ReadHandler) JitProvisionByEmail(ctx context.Context, req *identityv1.JitProvisionByEmailRequest) (*identityv1.JitProvisionByEmailResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	alias := strings.TrimSpace(req.GetConnectionAlias())
	var (
		u       store.User
		created bool
	)
	if h.jitDisabledForConnAlias(ctx, alias) {
		// An authorization decision: a deleted account is not a
		// pre-provisioned one, so only a live user counts.
		existing, err := h.store.FindLiveUserByEmail(ctx, email)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ssoJitDisabledError(ctx, email)
		}
		if err != nil {
			return nil, statusFromStoreErr(err)
		}
		u = existing
	} else {
		provisioned, c, err := h.store.JITProvisionByEmail(ctx, email, req.GetFirstName(), req.GetLastName())
		if err != nil {
			return nil, statusFromStoreErr(err)
		}
		u, created = provisioned, c
	}
	if created {
		emitSSOEvent(ctx, h.events, eventSSOAccountProvisioned, map[string]any{
			"email":  u.Email,
			"userId": u.ID.String(),
		})
		emitAccountCreated(ctx, h.acctCreatedPub, u.ID.String())
	}
	u, err := h.applyConnectionGroups(ctx, u, alias, req.GetIdpGroups())
	if err != nil {
		return nil, err
	}
	return &identityv1.JitProvisionByEmailResponse{User: userToProto(u)}, nil
}

// ListUsersInGroup enumerates users in a group, optionally including
// descendants.
func (h *ReadHandler) ListUsersInGroup(ctx context.Context, req *identityv1.ListUsersInGroupRequest) (*identityv1.ListUsersInGroupResponse, error) {
	id, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	us, err := h.store.ListUsersInGroup(ctx, id, req.GetIncludeDescendants())
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.User, 0, len(us))
	for _, u := range us {
		out = append(out, userToProto(u))
	}
	return &identityv1.ListUsersInGroupResponse{Users: out}, nil
}

// GetGroup returns a single group by id.
func (h *ReadHandler) GetGroup(ctx context.Context, req *identityv1.GetGroupRequest) (*identityv1.GetGroupResponse, error) {
	id, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	g, err := h.store.GetGroup(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.GetGroupResponse{Group: groupToProto(g)}, nil
}

// ListGroupDescendants returns every descendant of a group.
func (h *ReadHandler) ListGroupDescendants(ctx context.Context, req *identityv1.ListGroupDescendantsRequest) (*identityv1.ListGroupDescendantsResponse, error) {
	id, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	gs, err := h.store.ListDescendants(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.Group, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupToProto(g))
	}
	return &identityv1.ListGroupDescendantsResponse{Groups: out}, nil
}

// ListGroupAncestors returns the ancestor chain (leaf first, root last).
func (h *ReadHandler) ListGroupAncestors(ctx context.Context, req *identityv1.ListGroupAncestorsRequest) (*identityv1.ListGroupAncestorsResponse, error) {
	id, err := parseUUID(req.GetGroupId(), "group_id")
	if err != nil {
		return nil, err
	}
	gs, err := h.store.ListAncestors(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.Group, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupToProto(g))
	}
	return &identityv1.ListGroupAncestorsResponse{Groups: out}, nil
}

// ResolveEmail returns just the email field for a user — used by notify
// paths that don't need a full hydration.
func (h *ReadHandler) ResolveEmail(ctx context.Context, req *identityv1.ResolveEmailRequest) (*identityv1.ResolveEmailResponse, error) {
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.ResolveEmailResponse{Email: u.Email}, nil
}

// ResolveFCMToken returns the FCM push token for a user.
func (h *ReadHandler) ResolveFCMToken(ctx context.Context, req *identityv1.ResolveFCMTokenRequest) (*identityv1.ResolveFCMTokenResponse, error) {
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.ResolveFCMTokenResponse{FcmToken: u.FCMToken}, nil
}

// ListUserGroups returns the groups a user is a direct member of (or with
// descendants expanded — the gateway projection).
func (h *ReadHandler) ListUserGroups(ctx context.Context, req *identityv1.ListUserGroupsRequest) (*identityv1.ListUserGroupsResponse, error) {
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	gs, err := h.store.ListUserGroups(ctx, id, req.GetIncludeDescendants())
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.Group, 0, len(gs))
	for _, g := range gs {
		out = append(out, groupToProto(g))
	}
	return &identityv1.ListUserGroupsResponse{Groups: out}, nil
}

// ListUsersByEmail returns up to limit users whose email, username, first name,
// last name, or "first last" display name contains the given substring
// (case-insensitive). Despite the RPC/field name, the match is not email-only:
// it backs the user-picker typeahead, which must resolve a person by their name
// or login and not just their email address. Pagination is via an
// opaque cursor encoding the last returned (email, id) tuple; see
// encodeUserCursor / decodeUserCursor.
//
// Empty email_substring matches every user — admin CLI's `user list`
// passes "" when no --email-contains is supplied so this RPC backs both
// "search users" and "list all users" paths.
//
// Tombstoned users (soft-deleted or merged away) are excluded by DEFAULT
// so no picker can offer a deleted account as a merge target.
// Merely-disabled users are NOT excluded — a disabled duplicate is the
// canonical merge source. GetUser stays tombstone-blind so the gateway's
// resolveUserLabels can still render names for historical audit rows.
//
// include_deleted=true additionally returns them, each marked with
// User.deleted_at and, when merged away, User.merged_into_user_id
// . That exists because's exclusion left NO surface in
// the product listing a soft-deleted account — the gateway's admin directory
// resolver calls THIS RPC, the same one as the typeahead, so an administrator
// investigating "where did this person's records go" lost the ability to see
// that the account had existed and which account it was merged into. Only the
// admin directory may set it; the typeahead must not, and a caller that sets it
// must render tombstoned rows as closed/merged rather than selectable.
func (h *ReadHandler) ListUsersByEmail(ctx context.Context, req *identityv1.ListUsersByEmailRequest) (*identityv1.ListUsersByEmailResponse, error) {
	limit := clampLimit(req.GetLimit())
	cursorEmail, cursorID, err := decodeUserCursor(req.GetPageToken())
	if err != nil {
		return nil, err
	}
	users, err := h.store.SearchUsers(ctx, store.UserSearchOpts{
		Substring:      req.GetEmailSubstring(),
		Limit:          limit,
		CursorEmail:    cursorEmail,
		CursorID:       cursorID,
		IncludeDeleted: req.GetIncludeDeleted(),
	})
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.User, 0, len(users))
	for _, u := range users {
		out = append(out, userToProto(u))
	}
	next := ""
	if len(users) == limit {
		last := users[len(users)-1]
		next = encodeUserCursor(last.Email, last.ID)
	}
	return &identityv1.ListUsersByEmailResponse{Users: out, NextPageToken: next}, nil
}

// ListUsersByIdpGroups returns all platform users that have any of the
// supplied identity provider group names in their membership set.
func (h *ReadHandler) ListUsersByIdpGroups(ctx context.Context, req *identityv1.ListUsersByIdpGroupsRequest) (*identityv1.ListUsersByIdpGroupsResponse, error) {
	us, err := h.store.ListUsersByIdpGroups(ctx, req.GetIdpGroupNames())
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.User, 0, len(us))
	for _, u := range us {
		out = append(out, userToProto(u))
	}
	return &identityv1.ListUsersByIdpGroupsResponse{Users: out}, nil
}

// RevokeMySessions revokes every session of the calling user in Kratos.
func (h *ReadHandler) RevokeMySessions(ctx context.Context, _ *identityv1.RevokeMySessionsRequest) (*identityv1.RevokeMySessionsResponse, error) {
	sub, ok := callerSubject(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	id, err := parseUUID(sub, "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	n, err := revokeAllSessions(ctx, h.signIn, u)
	if err != nil {
		return nil, err
	}
	return &identityv1.RevokeMySessionsResponse{Revoked: safecast.Int32(n)}, nil
}

// CountUsersByIdpGroups returns the count of distinct platform users that
// belong to any of the supplied identity provider group names.
func (h *ReadHandler) CountUsersByIdpGroups(ctx context.Context, req *identityv1.CountUsersByIdpGroupsRequest) (*identityv1.CountUsersByIdpGroupsResponse, error) {
	n, err := h.store.CountUsersByIdpGroups(ctx, req.GetIdpGroupNames())
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.CountUsersByIdpGroupsResponse{Count: safecast.Int32(n)}, nil
}

// ListAllUsers returns every ENABLED platform user. It is the audience when a
// policy/group ack targets "Everyone".
func (h *ReadHandler) ListAllUsers(ctx context.Context, _ *identityv1.ListAllUsersRequest) (*identityv1.ListAllUsersResponse, error) {
	us, err := h.store.ListAllUsers(ctx)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.User, 0, len(us))
	for _, u := range us {
		out = append(out, userToProto(u))
	}
	return &identityv1.ListAllUsersResponse{Users: out}, nil
}

// CountAllUsers returns the count of ENABLED platform users — the audience size
// when ack targets "Everyone".
func (h *ReadHandler) CountAllUsers(ctx context.Context, _ *identityv1.CountAllUsersRequest) (*identityv1.CountAllUsersResponse, error) {
	n, err := h.store.CountAllUsers(ctx)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.CountAllUsersResponse{Count: safecast.Int32(n)}, nil
}

// ListUserIdpGroups returns the identity provider group names for a single user, keyed by the
// platform user id (users.id), not the external subject. Obligations uses this to
// resolve obligations from the userID carried on acks / forwarded by the
// gateway, which is the platform user id.
func (h *ReadHandler) ListUserIdpGroups(ctx context.Context, req *identityv1.ListUserIdpGroupsRequest) (*identityv1.ListUserIdpGroupsResponse, error) {
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	names, err := h.store.UserIdpGroups(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.ListUserIdpGroupsResponse{IdpGroups: names}, nil
}

// ListGroups returns up to limit groups under parent_id (empty = root-level).
// include_descendants=true expands to the transitive closure rooted at
// parent_id (combined with parent_id="" this yields the whole tree).
func (h *ReadHandler) ListGroups(ctx context.Context, req *identityv1.ListGroupsRequest) (*identityv1.ListGroupsResponse, error) {
	parent, err := parseOptionalUUID(req.GetParentId(), "parent_id")
	if err != nil {
		return nil, err
	}
	limit := clampLimit(req.GetLimit())
	cursorName, cursorID, err := decodeGroupCursor(req.GetPageToken())
	if err != nil {
		return nil, err
	}
	groups, err := h.store.ListGroups(ctx, parent, req.GetIncludeDescendants(), limit, cursorName, cursorID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.Group, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupToProto(g))
	}
	next := ""
	if len(groups) == limit {
		last := groups[len(groups)-1]
		next = encodeGroupCursor(last.Name, last.ID)
	}
	return &identityv1.ListGroupsResponse{Groups: out, NextPageToken: next}, nil
}

// clampLimit normalises the caller-supplied limit to [1, listPageMaxLimit]
// with listPageDefaultLimit on zero or negative.
func clampLimit(requested int32) int {
	if requested <= 0 {
		return listPageDefaultLimit
	}
	if requested > listPageMaxLimit {
		return listPageMaxLimit
	}
	return int(requested)
}

// encodeUserCursor packs (email, id) into an opaque, URL-safe token. The
// concrete shape is base64(email || 0x1f || id.String()) — chosen because
// 0x1f (unit separator) is illegal in email addresses so there's no risk of
// ambiguity when splitting on it.
func encodeUserCursor(email string, id uuid.UUID) string {
	raw := email + "\x1f" + id.String()
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

func decodeUserCursor(token string) (string, uuid.UUID, error) {
	if token == "" {
		return "", uuid.Nil, nil
	}
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", uuid.Nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	parts := strings.SplitN(string(raw), "\x1f", 2)
	if len(parts) != 2 {
		return "", uuid.Nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return "", uuid.Nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	return parts[0], id, nil
}

// encodeGroupCursor / decodeGroupCursor mirror the user variants on the
// (name, id) tuple. Same separator + base64 envelope.
func encodeGroupCursor(name string, id uuid.UUID) string {
	raw := name + "\x1f" + id.String()
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

func decodeGroupCursor(token string) (string, uuid.UUID, error) {
	if token == "" {
		return "", uuid.Nil, nil
	}
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", uuid.Nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	parts := strings.SplitN(string(raw), "\x1f", 2)
	if len(parts) != 2 {
		return "", uuid.Nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return "", uuid.Nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	return parts[0], id, nil
}

// guardNoIdentifyingClaims refuses to create an account from a sign-in that
// carries no email, username or name: a real sign-in always has one, so this
// only stops a caller passing something else (such as a row id) as the
// subject.
func guardNoIdentifyingClaims(ctx context.Context, subject, email, preferredUsername, name, firstName, lastName string) error {
	if email != "" || preferredUsername != "" || name != "" || firstName != "" || lastName != "" {
		return nil
	}
	lg := logger.Ctx(ctx)
	lg.Warn("refusing to JIT-provision user: no identifying claims (no email/preferred_username/name)", log.F("external_subject", subject))
	return status.Error(codes.InvalidArgument, "cannot provision user: no identifying claims")
}

// jitDisabledForConnAlias reports whether the IdP connection identified by
// alias has just-in-time provisioning turned off (jit_enabled=false,
// . It returns false (JIT allowed) when no alias is supplied or the
// connection can't be resolved, so JIT is only ever blocked for a KNOWN
// connection that explicitly opted out — the flag is a per-org opt-in, never a
// fail-open surprise for an un-aliased caller. Mirrors the group-mapping path,
// which likewise logs-and-continues on a connection lookup miss.
func (h *ReadHandler) jitDisabledForConnAlias(ctx context.Context, alias string) bool {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return false
	}
	conn, err := h.store.GetIdPConnectionByAlias(ctx, alias)
	if err != nil {
		return false
	}
	return !conn.JitEnabled
}

// ssoJitDisabledError is the fail-closed result returned when a first-seen SSO
// user tries to sign in to an org with jit_enabled=false: no
// auto-create, a stable coded PermissionDenied (Code 5004 / SSO_JIT_DISABLED)
// the gateway relays as a user-safe "ask your admin" message. subject is logged
// (external_subject or email) so the block is diagnosable.
func ssoJitDisabledError(ctx context.Context, subject string) error {
	lg := logger.Ctx(ctx)
	lg.Warn("refusing to JIT-provision SSO user: jit_enabled=false for the org connection — failing closed", log.F("subject", subject))
	return errcodes.Error(ctx, errcodes.SSOJitDisabled())
}

// GetSetupState reports whether the system needs first-run setup (no root user exists).
// Unauthenticated — self-guards via the no-root invariant.
func (h *ReadHandler) GetSetupState(ctx context.Context, _ *identityv1.GetSetupStateRequest) (*identityv1.GetSetupStateResponse, error) {
	has, err := h.store.HasRootUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "setup state: %v", err)
	}
	return &identityv1.GetSetupStateResponse{NeedsSetup: !has}, nil
}

// BootstrapRoot creates the first root admin: a Kratos identity with the
// password, then the local account, which the first sign-in adopts. It is
// unauthenticated and guards itself on the no-root rule; once a root exists
// it succeeds doing nothing, so a seed job can call it on every run.
func (h *ReadHandler) BootstrapRoot(ctx context.Context, req *identityv1.BootstrapRootRequest) (*identityv1.BootstrapRootResponse, error) {
	if req.GetUsername() == "" || req.GetEmail() == "" || req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "username, email, password required")
	}
	if usernameLooksLikeEmail(req.GetUsername()) {
		return nil, errUsernameIsEmail
	}
	has, err := h.store.HasRootUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "setup state: %v", err)
	}
	if has {
		lg := logger.Ctx(ctx)
		lg.Info("BootstrapRoot: root user already exists, no-op")
		return &identityv1.BootstrapRootResponse{}, nil
	}
	if h.signIn == nil {
		return nil, errcodes.Error(ctx, errcodes.LocalAccountsUnavailable())
	}
	name := req.GetName()
	if name == "" {
		name = req.GetUsername()
	}
	if _, err := h.signIn.CreateIdentity(ctx, kratos.Account{Username: req.GetUsername(), Email: req.GetEmail(), Name: name}, req.GetPassword()); err != nil {
		return nil, status.Errorf(codes.Internal, "create sign-in identity: %v", err)
	}
	u, err := h.store.PreCreateLocalUserRoot(ctx, req.GetUsername(), req.GetEmail(), name)
	if err != nil {
		// The single-root index is the atomic backstop against a concurrent
		// bootstrap.
		if errors.Is(err, store.ErrConflict) {
			return nil, status.Error(codes.FailedPrecondition, "a root user already exists")
		}
		return nil, status.Errorf(codes.Internal, "pre-create root: %v", err)
	}
	emitAccountCreated(ctx, h.acctCreatedPub, u.ID.String())
	return &identityv1.BootstrapRootResponse{User: userToProto(u)}, nil
}
