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

// MarkEmailVerified records that (user_id, email) proved control of the mailbox
// — the persistence half of the public email-verification link.
//
// Like the password-reset RPCs on IdentityReadService it is UNAUTHENTICATED and
// self-guards on the credential the caller already validated: the gateway's
// public /notify/verify-email edge has verified the stateless signed
// PurposeEmailVerify token (HMAC-SHA256, shared NOTIFY_UNSUB_SECRET) that
// carries this same (user_id, email), so there is no session/claims gate here —
// the token IS the credential. It never trusts the request for authorization,
// only for the identifiers to persist.
//
// Idempotent: re-verifying an already-verified address returns
// already_verified=true with no second write. The store re-checks email against
// the account's CURRENT address, so a token minted for a since-changed address
// is refused (FailedPrecondition) rather than silently honored.
func (h *ReadHandler) MarkEmailVerified(ctx context.Context, req *identityv1.MarkEmailVerifiedRequest) (*identityv1.MarkEmailVerifiedResponse, error) {
	uid, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	email := strings.TrimSpace(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email must not be empty")
	}
	already, err := h.store.MarkEmailVerified(ctx, uid, email)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.MarkEmailVerifiedResponse{AlreadyVerified: already}, nil
}
