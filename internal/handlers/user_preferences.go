// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"strings"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/text/language"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// UpdateUserPreferences sets ANOTHER user's language for a site administrator
// (steward-identity#38). A person already sets their own through
// UpdateMyProfile; this is the admin path the admin user page needs.
//
// The locale is an identity fact on the account row, not a directory field, so
// local and directory (SSO) accounts alike take it and the sign-in service is
// never called. Only the locale changes: the name, e-mail and time zone are
// left exactly as they were. The change is audited under the administrator.
func (h *AdminHandler) UpdateUserPreferences(ctx context.Context, req *identityv1.UpdateUserPreferencesRequest) (*identityv1.UpdateUserPreferencesResponse, error) {
	lg := logger.Ctx(ctx)
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		lg.Debug("update user preferences: refused, not a site admin")
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	cur, err := h.store.GetUser(ctx, id)
	if err != nil {
		lg.Debug("update user preferences: user lookup failed", log.F("user_id", id.String()), log.F("error", errText(err)))
		return nil, statusFromStoreErr(err)
	}
	if req.Locale == nil {
		lg.Debug("update user preferences: nothing to change", log.F("user_id", id.String()))
		return &identityv1.UpdateUserPreferencesResponse{User: userToProto(cur)}, nil
	}
	locale := strings.TrimSpace(req.GetLocale())
	if locale != "" {
		if _, err := language.Parse(locale); err != nil {
			lg.Debug("update user preferences: locale is not a BCP 47 tag", log.F("user_id", id.String()))
			return nil, status.Error(codes.InvalidArgument, "locale must be a BCP 47 language tag such as en-US")
		}
	}
	if locale == cur.Locale {
		return &identityv1.UpdateUserPreferencesResponse{User: userToProto(cur)}, nil
	}
	updated, err := h.store.SetUserLocale(ctx, id, locale, actorUUIDPtr(actor), actor.ActorExternal)
	if err != nil {
		lg.Error(err, "update user preferences: write failed", log.F("user_id", id.String()))
		return nil, statusFromStoreErr(err)
	}
	lg.Info("update user preferences: locale set", log.F("user_id", id.String()))
	return &identityv1.UpdateUserPreferencesResponse{User: userToProto(updated)}, nil
}
