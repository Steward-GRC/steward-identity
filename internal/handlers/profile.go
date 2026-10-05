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

// UpdateMyProfile lets the CALLING user edit their OWN display name.
//
// Like CompleteOnboarding, and unlike the surrounding IdentityAdminService RPCs,
// it is NOT gated on site-admin (it deliberately does not call h.auth.Authorize):
// the subject is the authenticated platform user resolved directly from the
// gateway-forwarded claims, so any signed-in user can edit their OWN profile —
// and only their own, since the id is never taken from the request. The separate
// admin path for editing OTHER users is UpdateUserProfile.
//
// first_name and last_name are presence-tracked optionals: an omitted (nil)
// field leaves the stored value unchanged, a present field sets it (trimmed).
// The display name is NOT an input — it is DERIVED from first_name + last_name
// (name = "first last"), matching onboarding. We compute the effective values
// against the current row and write once, only when something actually changed
// (store.UpdateUserProfile sets name/first/last together; email is unchanged
// here so we pass the current address through).
//
// SSO and local users may both edit here. The subject-keyed JIT upsert
// overwrites the name parts from the identity provider on the next SSO
// sign-in, so an SSO user's local edit lasts until then; the by-email JIT
// path keeps it.
func (h *AdminHandler) UpdateMyProfile(ctx context.Context, req *identityv1.UpdateMyProfileRequest) (*identityv1.UpdateMyProfileResponse, error) {
	sub, ok := callerSubject(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	uid, err := parseUUID(sub, "user_id")
	if err != nil {
		return nil, err
	}

	cur, err := h.store.GetUser(ctx, uid)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	first := cur.FirstName
	if req.FirstName != nil {
		first = strings.TrimSpace(req.GetFirstName())
	}
	last := cur.LastName
	if req.LastName != nil {
		last = strings.TrimSpace(req.GetLastName())
	}
	// timezone/locale are identity facts consumed by the obligations service (quiet
	// hours / digest windows); presence-tracked like the name parts. An omitted
	// field leaves the stored value unchanged; a present field sets it (trimmed).
	tz := cur.Timezone
	if req.Timezone != nil {
		tz = strings.TrimSpace(req.GetTimezone())
	}
	locale := cur.Locale
	if req.Locale != nil {
		locale = strings.TrimSpace(req.GetLocale())
	}
	// Display name is derived from the parts whenever either is present; when both
	// resolve empty the existing display name is left untouched (never clobbered
	// to empty), matching onboarding.
	name := cur.Name
	if first != "" || last != "" {
		name = strings.TrimSpace(first + " " + last)
	}

	updated := cur
	if name != cur.Name || first != cur.FirstName || last != cur.LastName || tz != cur.Timezone || locale != cur.Locale {
		updated, err = h.store.UpdateUserProfile(ctx, uid, cur.Email, name, first, last, tz, locale)
		if err != nil {
			return nil, statusFromStoreErr(err)
		}
		// A local account's Kratos traits follow the row.
		if updated.LocalAccount && h.accounts != nil {
			identityID, found, err := kratosIdentityID(ctx, h.accounts, updated)
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "find sign-in identity: %v", err)
			}
			if found {
				if err := h.accounts.UpdateProfile(ctx, identityID, updated.Email, name); err != nil {
					return nil, status.Errorf(codes.Internal, "update sign-in identity: %v", err)
				}
			}
		}
	}

	return &identityv1.UpdateMyProfileResponse{User: userToProto(updated)}, nil
}
