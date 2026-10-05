// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// Admin MFA factor management + #22): the ADMIN side of the shared
// profile Security tab. A site-admin views, resets (removes) and relabels a
// TARGET user's second factors. These mirror the caller-scoped self-service RPCs
// (ListUserFactors / RemoveFactor / RenameMFAMethod on ReadHandler) but live on
// AdminHandler and are gated by h.auth.Authorize (admin CLI mTLS or the forwarded
// site-admin role, exactly like UpdateUserProfile). The subject is the target
// user_id carried on the request; the acting admin (resolved from the gate) is
// the audit actor. Non-admin callers get PermissionDenied.

// adminMFALabelMaxLen bounds an admin-supplied factor label so a runaway value
// can never bloat the row or the factor-management UI.
const adminMFALabelMaxLen = 128

// rfc3339Z is the timestamp format the factor list uses, matching the
// self-service ListUserFactors handler.
const rfc3339Z = "2006-01-02T15:04:05Z07:00"

// AdminListUserFactors reports the target user's enrolled second factors for the
// admin Security tab. Unlike the self-service ListUserFactors (which aggregates
// all passkeys into one entry), this emits one factor per passkey so each is
// individually addressable by AdminRemoveUserFactor / AdminRenameUserFactor. Each
// factor carries a stable id: "totp", the passkey credential id, or "email".
func (h *AdminHandler) AdminListUserFactors(ctx context.Context, req *identityv1.AdminListUserFactorsRequest) (*identityv1.AdminListUserFactorsResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}

	factors := []*identityv1.UserFactor{}

	confirmedAt, label, err := h.store.AdminTotpFactor(ctx, id)
	switch {
	case err == nil:
		if confirmedAt != nil {
			factors = append(factors, &identityv1.UserFactor{
				Id:         factorKindTotp,
				Kind:       factorKindTotp,
				EnrolledAt: confirmedAt.UTC().Format(rfc3339Z),
				Label:      label,
			})
		}
	case errors.Is(err, store.ErrNotFound):
		// no TOTP enrollment — fine
	default:
		return nil, statusFromStoreErr(err)
	}

	passkeys, err := h.store.ListWebauthnCredentials(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	for _, c := range passkeys {
		factors = append(factors, &identityv1.UserFactor{
			Id:         c.CredentialID,
			Kind:       factorKindPasskey,
			EnrolledAt: c.CreatedAt.UTC().Format(rfc3339Z),
			Label:      c.Label,
		})
	}

	if u.Email != "" {
		factors = append(factors, &identityv1.UserFactor{
			Id:   factorKindEmail,
			Kind: factorKindEmail,
		})
	}

	return &identityv1.AdminListUserFactorsResponse{Factors: factors}, nil
}

// AdminRemoveUserFactor resets (removes) one of the target user's factors so
// they can re-enroll, addressed by method_id: "totp" removes the TOTP
// enrollment; any other value is a passkey credential id and removes that single
// passkey. The implicit "email" factor cannot be removed (FailedPrecondition).
func (h *AdminHandler) AdminRemoveUserFactor(ctx context.Context, req *identityv1.AdminRemoveUserFactorRequest) (*identityv1.AdminRemoveUserFactorResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	methodID := req.GetMethodId()
	if methodID == "" {
		return nil, status.Error(codes.InvalidArgument, "method_id required")
	}
	switch methodID {
	case factorKindTotp:
		if err := h.store.AdminDeleteTotp(ctx, id, actorUUIDPtr(actor), actor.ActorExternal); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no totp enrollment to remove")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.AdminRemoveUserFactorResponse{}, nil
	case factorKindEmail:
		return nil, status.Error(codes.FailedPrecondition, "the email factor is implicit and cannot be removed")
	default:
		// Any other method id is a passkey credential id.
		if err := h.store.AdminDeleteWebauthnCredential(ctx, id, methodID, actorUUIDPtr(actor), actor.ActorExternal); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no such passkey to remove")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.AdminRemoveUserFactorResponse{}, nil
	}
}

// AdminRenameUserFactor sets the user-facing label on one of the target user's
// factors, addressed by method_id ("totp" or a passkey credential id). label ""
// clears it back to the client default. The implicit "email" factor cannot be
// labelled (FailedPrecondition).
func (h *AdminHandler) AdminRenameUserFactor(ctx context.Context, req *identityv1.AdminRenameUserFactorRequest) (*identityv1.AdminRenameUserFactorResponse, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	methodID := req.GetMethodId()
	if methodID == "" {
		return nil, status.Error(codes.InvalidArgument, "method_id required")
	}
	label := req.GetLabel()
	if len(label) > adminMFALabelMaxLen {
		return nil, status.Errorf(codes.InvalidArgument, "label too long (max %d characters)", adminMFALabelMaxLen)
	}
	switch methodID {
	case factorKindTotp:
		if err := h.store.AdminRenameTotp(ctx, id, label, actorUUIDPtr(actor), actor.ActorExternal); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no totp enrollment to rename")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.AdminRenameUserFactorResponse{}, nil
	case factorKindEmail:
		return nil, status.Error(codes.FailedPrecondition, "the email factor is implicit and cannot be labelled")
	default:
		// Any other method id is a passkey credential id.
		if err := h.store.AdminRenameWebauthnCredential(ctx, id, methodID, label, actorUUIDPtr(actor), actor.ActorExternal); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no such passkey to rename")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.AdminRenameUserFactorResponse{}, nil
	}
}
