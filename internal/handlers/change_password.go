// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// passwordChanger changes a person's own password through the sign-in
// service's public flows: it proves current, then sets next under the
// service's password policy. *kratos.Public implements it.
type passwordChanger interface {
	ChangePassword(ctx context.Context, identifier, current, next string) error
}

// WithPasswordChanger wires the self-service password change. Unset, the RPC
// answers a coded "unavailable" error.
func (h *ReadHandler) WithPasswordChanger(p passwordChanger) *ReadHandler {
	h.passwords = p
	return h
}

var errNoPasswordChanger = errors.New("identity: the Kratos public API isn't configured")

// ChangeMyPassword changes the calling user's own password
// (steward-identity#66). The user is the forwarded actor, never a request
// field, so nobody can change another person's password this way. Neither
// password is logged, audited or put in an error.
func (h *ReadHandler) ChangeMyPassword(ctx context.Context, req *identityv1.ChangeMyPasswordRequest) (*identityv1.ChangeMyPasswordResponse, error) {
	lg := logger.Ctx(ctx)
	log.Trace(lg, "change my password: entry")
	sub, ok := callerSubject(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		lg.Debug("change my password: refused while acting as another user")
		return nil, err
	}
	if req.GetCurrentPassword() == "" || req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "current_password and new_password required")
	}
	uid, err := parseUUID(sub, "user_id")
	if err != nil {
		return nil, err
	}
	u, err := h.store.GetUser(ctx, uid)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if h.signIn == nil || h.passwords == nil {
		lg.Warn("change my password: the sign-in service is not configured", log.F("user_id", u.ID.String()))
		return nil, errcodes.Error(ctx, errcodes.PasswordChangeUnavailable(errNoPasswordChanger))
	}
	// An account that signs in through an identity provider has no Kratos
	// password identity; ask Kratos so a stale local flag can't misreport.
	if !u.LocalAccount {
		lg.Debug("change my password: the account has no local password", log.F("user_id", u.ID.String()))
		return nil, errcodes.Error(ctx, errcodes.NoLocalPassword())
	}
	if _, found, err := kratosIdentityID(ctx, h.signIn, u); err != nil {
		lg.Error(err, "change my password: sign-in identity lookup failed", log.F("user_id", u.ID.String()))
		return nil, errcodes.Error(ctx, errcodes.PasswordChangeUnavailable(err))
	} else if !found {
		lg.Debug("change my password: no sign-in identity", log.F("user_id", u.ID.String()))
		return nil, errcodes.Error(ctx, errcodes.NoLocalPassword())
	}

	err = h.passwords.ChangePassword(ctx, u.Email, req.GetCurrentPassword(), req.GetNewPassword())
	switch {
	case err == nil:
		lg.Info("change my password: changed", log.F("user_id", u.ID.String()))
		h.auditPasswordChange(ctx, u, "user.password.changed", map[string]any{"method": "self_service"})
		return &identityv1.ChangeMyPasswordResponse{}, nil
	case errors.Is(err, kratos.ErrWrongPassword):
		lg.Info("change my password: wrong current password", log.F("user_id", u.ID.String()))
		h.auditPasswordChange(ctx, u, "user.password.change_failed", map[string]any{"method": "self_service", "reason": "wrong_current_password"})
		return nil, errcodes.Error(ctx, errcodes.CurrentPasswordWrong())
	case errors.Is(err, kratos.ErrWeakPassword):
		lg.Info("change my password: refused by the password policy", log.F("user_id", u.ID.String()))
		h.auditPasswordChange(ctx, u, "user.password.change_failed", map[string]any{"method": "self_service", "reason": "weak_new_password"})
		return nil, errcodes.Error(ctx, errcodes.PasswordTooWeak())
	default:
		lg.Error(err, "change my password: sign-in service failed", log.F("user_id", u.ID.String()))
		return nil, errcodes.Error(ctx, errcodes.PasswordChangeUnavailable(err))
	}
}

// auditPasswordChange records a password change attempt for u. The payload
// carries no password. A failed write is logged: the change has its answer.
func (h *ReadHandler) auditPasswordChange(ctx context.Context, u store.User, eventType string, payload map[string]any) {
	id := u.ID
	if err := h.store.EmitAudit(ctx, store.AuditEvent{
		EventType: eventType, ActorUserID: &id, TargetUserID: &id, Payload: payload,
	}); err != nil {
		lg := logger.Ctx(ctx)
		lg.Warn("change my password: audit write failed", log.F("user_id", u.ID.String()), log.F("error", errText(err)))
	}
}
