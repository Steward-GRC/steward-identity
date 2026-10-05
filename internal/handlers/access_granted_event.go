// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

// emitAccessGranted publishes sso.access_granted for a successful,
// membership-changing admin grant (AddUserToGroup / GrantRole). Guarded by
// the caller on two fronts before it is ever invoked: the grant must have
// actually changed membership (not a no-op re-grant), and userEmail must be
// resolvable — an empty email here is a final belt-and-braces guard so a user
// with no resolvable address never produces an unroutable event.
//
// The vars shape matches the wire contract already shipped for
// this same event (sso.access_granted -> access-granted template, which reads
// email + groups []string): "groups" carries the single grant description as
// a one-element slice so the existing template renders it exactly like the
// JIT group-mapping path. "grant" is also included (the brief's literal ask)
// as a convenience singular field; the shipped template ignores unknown
// props, so carrying both is harmless.
func (h *AdminHandler) emitAccessGranted(ctx context.Context, userID, userEmail, grant string) {
	if userEmail == "" {
		return
	}
	emitSSOEvent(ctx, h.ssoEvents, eventSSOAccessGranted, map[string]any{
		"userId": userID,
		"email":  userEmail,
		"grant":  grant,
		"groups": []string{grant},
	})
}

// emitAccessGrantedForGroup resolves the granted user's email and the
// group's display name and emits sso.access_granted. Best-effort: a lookup
// failure (the user/group were just written to in the same RPC, so this is
// only realistically hit under a concurrent delete) skips the emit rather
// than failing the already-committed AddUserToGroup RPC.
func (h *AdminHandler) emitAccessGrantedForGroup(ctx context.Context, userID, groupID uuid.UUID) {
	u, err := h.store.GetUser(ctx, userID)
	if err != nil {
		return
	}
	g, err := h.store.GetGroup(ctx, groupID)
	if err != nil {
		return
	}
	h.emitAccessGranted(ctx, userID.String(), u.Email, g.Name)
}

// hasRole reports whether u already holds role (scoped to category when
// category is non-empty, global otherwise). Used by GrantRole to tell a
// genuinely new grant apart from a no-op re-grant of a role the user already
// has, so the access-granted notification fires only once per real grant.
func hasRole(u store.User, role, category string) bool {
	if category == "" {
		return slices.Contains(u.Roles, role)
	}
	for _, sr := range u.ScopedRoles {
		if sr.Role == role && sr.Category == category {
			return true
		}
	}
	return false
}

// grantDescription renders a role+category pair as the human-readable string
// the access-granted email shows (e.g. "author (IT Security)" for a scoped
// role, or just "site-admin" for a global one).
func grantDescription(role, category string) string {
	if category == "" {
		return role
	}
	return role + " (" + category + ")"
}
