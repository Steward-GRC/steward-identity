// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"

	"github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mailSender delivers one plain-text message; *email.Mailer implements it.
type mailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// otpDeps bundles the wiring for the email-OTP flows (password reset +
// local-login 2FA). It hangs off ReadHandler; when nil, the OTP RPCs return
// Unavailable (feature not configured).
type otpDeps struct {
	sender          mailSender
	log             zerolog.Logger
	login2FAEnabled bool
	devEcho         bool // log freshly-minted codes for dev ergonomics
}

// WithOTP wires the OTP dependencies onto the read handler. Passing sender=nil
// still enables the flows over dev-echo alone (no mail), which is fine for
// local testing; in prod a real Sender must be supplied.
func (h *ReadHandler) WithOTP(sender mailSender, log zerolog.Logger, login2FAEnabled, devEcho bool) *ReadHandler {
	h.otp = &otpDeps{sender: sender, log: log, login2FAEnabled: login2FAEnabled, devEcho: devEcho}
	return h
}

// GetAuthConfig returns non-secret pre-login auth toggles. Always available
// (login2FAEnabled defaults to false when OTP is unwired), so the UI can safely
// read it before deciding whether to require the second factor.
//
// SsoAvailable is computed from HasActiveSSO and fails SAFE to false: if the
// store read errors, the UI simply shows the "Sign in with SSO" button disabled
// rather than offering a path that couldn't work anyway — the normal
// password/break-glass login is never blocked by this call.
func (h *ReadHandler) GetAuthConfig(ctx context.Context, _ *identityv1.GetAuthConfigRequest) (*identityv1.GetAuthConfigResponse, error) {
	enabled := false
	if h.otp != nil {
		enabled = h.otp.login2FAEnabled
	}
	ssoAvailable, err := h.store.HasActiveSSO(ctx)
	if err != nil {
		ssoAvailable = false
	}
	return &identityv1.GetAuthConfigResponse{Login_2FaEnabled: enabled, SsoAvailable: ssoAvailable}, nil
}

// RequestPasswordReset mints a password_reset OTP for the local user with the
// given email and emails it. It ALWAYS returns a generic success response so a
// caller cannot tell whether the email exists, is federated, or is local — no
// account enumeration. Real failures (email miss, federated account, rate
// limit) are logged server-side but never surfaced.
func (h *ReadHandler) RequestPasswordReset(ctx context.Context, req *identityv1.RequestPasswordResetRequest) (*identityv1.RequestPasswordResetResponse, error) {
	if h.otp == nil {
		return nil, status.Error(codes.Unavailable, "otp not configured")
	}
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	h.issueCode(ctx, "", req.GetEmail(), store.OTPPurposePasswordReset, "Your password reset code",
		"Use this code to reset your Steward password")
	return &identityv1.RequestPasswordResetResponse{}, nil
}

// ResetPasswordWithCode verifies the password_reset OTP for the email and, on
// success, sets the new password in Kratos.
// A bad/expired/used code returns InvalidArgument (indistinguishable failures).
func (h *ReadHandler) ResetPasswordWithCode(ctx context.Context, req *identityv1.ResetPasswordWithCodeRequest) (*identityv1.ResetPasswordWithCodeResponse, error) {
	if h.otp == nil {
		return nil, status.Error(codes.Unavailable, "otp not configured")
	}
	if req.GetEmail() == "" || req.GetCode() == "" || req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "email, code, and new_password required")
	}
	if h.signIn == nil {
		return nil, errcodes.Error(ctx, errcodes.LocalAccountsUnavailable())
	}
	u, err := h.store.GetLocalUserByEmail(ctx, req.GetEmail())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// No local user: treat as a bad code (don't reveal existence).
			return nil, status.Error(codes.InvalidArgument, "invalid or expired code")
		}
		return nil, statusFromStoreErr(err)
	}
	if err := h.store.VerifyOTP(ctx, u.ID, store.OTPPurposePasswordReset, req.GetCode()); err != nil {
		if errors.Is(err, store.ErrOTPInvalid) {
			return nil, status.Error(codes.InvalidArgument, "invalid or expired code")
		}
		return nil, statusFromStoreErr(err)
	}
	identityID, found, err := kratosIdentityID(ctx, h.signIn, u)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "find sign-in identity: %v", err)
	}
	if !found {
		return nil, status.Error(codes.FailedPrecondition, "the account has no local password")
	}
	if err := h.signIn.SetPassword(ctx, identityID, req.GetNewPassword()); err != nil {
		return nil, status.Errorf(codes.Internal, "set password: %v", err)
	}
	return &identityv1.ResetPasswordWithCodeResponse{}, nil
}

// RequestLoginOtp mints a login_2fa OTP for a local user (by username or email)
// and emails it. Same generic-success, anti-enumeration posture as
// RequestPasswordReset. The UI calls this only after the primary password has
// already been validated; the backend does not re-check the password here.
func (h *ReadHandler) RequestLoginOtp(ctx context.Context, req *identityv1.RequestLoginOtpRequest) (*identityv1.RequestLoginOtpResponse, error) {
	if h.otp == nil {
		return nil, status.Error(codes.Unavailable, "otp not configured")
	}
	if req.GetUsername() == "" && req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "username or email required")
	}
	h.issueCode(ctx, req.GetUsername(), req.GetEmail(), store.OTPPurposeLogin2FA, "Your sign-in verification code",
		"Use this code to complete signing in to Steward")
	return &identityv1.RequestLoginOtpResponse{}, nil
}

// VerifyLoginOtp verifies a login_2fa OTP for the identified local user. It only
// reports pass/fail; the UI holds the app session until this returns
// verified=true. The session is untouched.
func (h *ReadHandler) VerifyLoginOtp(ctx context.Context, req *identityv1.VerifyLoginOtpRequest) (*identityv1.VerifyLoginOtpResponse, error) {
	if h.otp == nil {
		return nil, status.Error(codes.Unavailable, "otp not configured")
	}
	if req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "code required")
	}
	u, ok := h.lookupLocalUser(ctx, req.GetUsername(), req.GetEmail())
	if !ok {
		// Unknown user: a plain failed verification (no enumeration).
		return &identityv1.VerifyLoginOtpResponse{Verified: false}, nil
	}
	if err := h.store.VerifyOTP(ctx, u.ID, store.OTPPurposeLogin2FA, req.GetCode()); err != nil {
		if errors.Is(err, store.ErrOTPInvalid) {
			return &identityv1.VerifyLoginOtpResponse{Verified: false}, nil
		}
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.VerifyLoginOtpResponse{Verified: true}, nil
}

// issueCode resolves the local user (by username/email), mints a code, emails
// it, and dev-echoes it. It NEVER returns an error to the caller (generic
// success is the anti-enumeration contract); every failure is logged only.
func (h *ReadHandler) issueCode(ctx context.Context, username, emailAddr, purpose, subject, blurb string) {
	// Ctx-aware logger: attaches trace_id/span_id so these OTP log lines
	// correlate with the RPC's trace in the tracing backend.
	lg := logger.Ctx(ctx)
	u, ok := h.lookupLocalUser(ctx, username, emailAddr)
	if !ok {
		lg.Info("otp request for unknown/non-local account — no email sent", log.F("purpose", purpose))
		return
	}
	code, err := h.store.GenerateOTP(ctx, u.ID, purpose)
	if err != nil {
		lg.Warn("otp generate failed", log.F("purpose", purpose), log.F("user_id", u.ID.String()), log.F("error", errText(err)))
		return
	}
	if h.otp.devEcho {
		// Dev ergonomics: surface the code in the log like the /setup token, so
		// it is testable without opening a mail catcher. Never enabled in prod.
		lg.Info("DEV: one-time code (OTP_DEV_ECHO)", log.F("purpose", purpose), log.F("email", u.Email), log.F("otp_code", code))
	}
	if h.otp.sender != nil && u.Email != "" {
		body := blurb + ":\n\n    " + code + "\n\nThis code expires in 10 minutes. If you did not request it, ignore this email."
		if err := h.otp.sender.Send(ctx, u.Email, subject, body); err != nil {
			lg.Warn("otp email send failed", log.F("email", u.Email), log.F("error", errText(err)))
		}
	}
}

// lookupLocalUser resolves a LOCAL user by email (preferred) then username.
// Returns ok=false when no local user matches — callers translate that into a
// generic non-committal response.
func (h *ReadHandler) lookupLocalUser(ctx context.Context, username, emailAddr string) (store.User, bool) {
	if emailAddr != "" {
		if u, err := h.store.GetLocalUserByEmail(ctx, emailAddr); err == nil {
			return u, true
		}
	}
	if username != "" {
		if u, err := h.store.GetUserByUsername(ctx, username); err == nil && u.LocalAccount {
			return u, true
		}
	}
	return store.User{}, false
}
