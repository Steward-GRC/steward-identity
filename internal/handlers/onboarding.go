// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// CompleteOnboarding marks the CALLING user's first-run onboarding done.
//
// Unlike the surrounding IdentityAdminService RPCs it is NOT gated on
// site-admin (it deliberately does not call h.auth.Authorize): the subject is
// the authenticated platform user resolved directly from the gateway-forwarded
// claims, so any signed-in user can complete their OWN onboarding — and only
// their own, since the id is never taken from the request. accept_terms MUST be
// true; first_name, last_name, email and username are optional,
// presence-tracked updates. The display name is NOT an input — it is derived
// from first_name + last_name. The RPC updates the structured profile (first/
// last name, email; name recomputed) via the existing profile path, optionally
// updates the (unique) username, records terms acceptance, sets
// onboarding_complete, and returns the updated user. (The proto still carries a
// legacy `name` field for wire-compat; it is ignored.)
func (h *AdminHandler) CompleteOnboarding(ctx context.Context, req *identityv1.CompleteOnboardingRequest) (*identityv1.CompleteOnboardingResponse, error) {
	sub, ok := callerSubject(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	if !req.GetAcceptTerms() {
		return nil, status.Error(codes.InvalidArgument, "accept_terms must be true")
	}
	uid, err := parseUUID(sub, "user_id")
	if err != nil {
		return nil, err
	}

	// Optional profile confirmation/update captured on the /welcome page. The
	// request carries first_name/last_name/email as presence-tracked optionals:
	// an omitted (nil) field leaves the stored value unchanged, while a present
	// field sets whatever the user confirmed or edited. The display `name` is NOT
	// a separate input — it is DERIVED from the structured parts (name =
	// "first last"). We compute the effective values against the current row and
	// write once, only when something actually changed (UpdateUserProfile sets
	// name/email/first/last together, so we pass the full effective tuple).
	if req.FirstName != nil || req.LastName != nil || req.Email != nil {
		cur, err := h.store.GetUser(ctx, uid)
		if err != nil {
			return nil, statusFromStoreErr(err)
		}
		email := cur.Email
		if req.Email != nil {
			if e := strings.TrimSpace(req.GetEmail()); e != "" {
				email = e
			}
		}
		first := cur.FirstName
		if req.FirstName != nil {
			first = strings.TrimSpace(req.GetFirstName())
		}
		last := cur.LastName
		if req.LastName != nil {
			last = strings.TrimSpace(req.GetLastName())
		}
		// Display name is derived from the parts whenever either is present.
		name := cur.Name
		if first != "" || last != "" {
			name = strings.TrimSpace(first + " " + last)
		}
		if email != cur.Email || name != cur.Name || first != cur.FirstName || last != cur.LastName {
			if _, err := h.store.UpdateUserProfile(ctx, uid, email, name, first, last, cur.Timezone, cur.Locale); err != nil {
				return nil, statusFromStoreErr(err)
			}
		}
	}

	// Optional username update. When provided it must be non-empty and unique;
	// the store maps a collision to ErrConflict (-> AlreadyExists).
	if req.Username != nil {
		username := strings.TrimSpace(req.GetUsername())
		if username == "" {
			return nil, status.Error(codes.InvalidArgument, "username must not be empty when provided")
		}
		if _, err := h.store.UpdateUsername(ctx, uid, username); err != nil {
			return nil, statusFromStoreErr(err)
		}
	}

	u, err := h.store.CompleteOnboarding(ctx, uid)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.CompleteOnboardingResponse{User: userToProto(u)}, nil
}
