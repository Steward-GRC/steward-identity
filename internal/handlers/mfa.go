// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"strings"

	"github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/secrets"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MFA second factors: TOTP (authenticator
// app) + email OTP. Identity is the factor authority — the BFF drives these
// RPCs during its 2-step login and the enrollment widget's flows. All RPCs
// are keyed by platform user_id.
//
// Factor kinds. "passkey" (WebAuthn) lives in webauthn.go.
const (
	factorKindTotp    = "totp"
	factorKindEmail   = "email"
	factorKindPasskey = "passkey"
)

// totpIssuer is the issuer label shown in authenticator apps.
const totpIssuer = "Steward"

// mfaDeps bundles the MFA wiring: the at-rest cipher for TOTP secrets, the
// email sender for OTP delivery, and dev-echo ergonomics. Hangs off
// ReadHandler; when nil, the MFA RPCs return Unavailable.
type mfaDeps struct {
	cipher  *secrets.Cipher
	sender  mailSender
	log     zerolog.Logger
	devEcho bool // log freshly-minted codes for dev ergonomics
}

// WithMFA wires the MFA dependencies onto the read handler. cipher=nil
// disables the TOTP RPCs (Unavailable) while leaving email OTP available;
// sender=nil leaves email OTP to dev-echo alone (fine for local testing).
func (h *ReadHandler) WithMFA(cipher *secrets.Cipher, sender mailSender, log zerolog.Logger, devEcho bool) *ReadHandler {
	h.mfa = &mfaDeps{cipher: cipher, sender: sender, log: log, devEcho: devEcho}
	return h
}

// mfaUser parses the user_id and loads the user row (factor RPCs are internal
// and user_id-keyed, so a miss is a plain NotFound — no enumeration posture
// needed on this surface).
func (h *ReadHandler) mfaUser(ctx context.Context, userID string) (store.User, error) {
	uid, err := parseUUID(userID, "user_id")
	if err != nil {
		return store.User{}, err
	}
	u, err := h.store.GetUser(ctx, uid)
	if err != nil {
		return store.User{}, statusFromStoreErr(err)
	}
	return u, nil
}

// totpCipher returns the at-rest cipher or Unavailable when TOTP is not
// configured (no TOTP_ENC_KEY).
func (h *ReadHandler) totpCipher() (*secrets.Cipher, error) {
	if h.mfa == nil || h.mfa.cipher == nil {
		return nil, status.Error(codes.Unavailable, "totp not configured")
	}
	return h.mfa.cipher, nil
}

// --- TOTP ---

// EnrollTotpBegin mints a fresh TOTP secret for the user, stores it encrypted
// (AES-256-GCM, unconfirmed), and returns the otpauth:// URI for the widget's
// QR plus a redacted secret hint. A confirmed enrollment is never replaced
// (AlreadyExists — RemoveFactor first); a pending one is restarted.
func (h *ReadHandler) EnrollTotpBegin(ctx context.Context, req *identityv1.EnrollTotpBeginRequest) (*identityv1.EnrollTotpBeginResponse, error) {
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	cipher, err := h.totpCipher()
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	account := u.Email
	if account == "" {
		account = u.Username
	}
	if account == "" {
		account = u.ID.String()
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: totpIssuer, AccountName: account})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate totp secret: %v", err)
	}
	sealed, err := cipher.Seal(key.Secret())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "seal totp secret: %v", err)
	}
	if err := h.store.UpsertPendingTotp(ctx, u.ID, sealed); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, status.Error(codes.AlreadyExists, "totp already enrolled; remove the factor first")
		}
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.EnrollTotpBeginResponse{
		OtpauthUri:   key.URL(),
		SecretMasked: maskSecret(key.Secret()),
	}, nil
}

// EnrollTotpConfirm proves possession of the pending secret with a current
// code (±1 period skew) and activates the enrollment. A wrong code is
// InvalidArgument; no pending enrollment is FailedPrecondition.
func (h *ReadHandler) EnrollTotpConfirm(ctx context.Context, req *identityv1.EnrollTotpConfirmRequest) (*identityv1.EnrollTotpConfirmResponse, error) {
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	cipher, err := h.totpCipher()
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "code required")
	}
	cred, err := h.store.GetTotp(ctx, u.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Error(codes.FailedPrecondition, "no totp enrollment in progress")
		}
		return nil, statusFromStoreErr(err)
	}
	secret, err := cipher.Open(cred.EncryptedSecret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open totp secret: %v", err)
	}
	// totp.Validate uses the RFC 6238 defaults: 30s period, 6 digits, SHA1,
	// ±1 period skew — exactly the authenticator-app contract.
	if !totp.Validate(req.GetCode(), secret) {
		return nil, status.Error(codes.InvalidArgument, "invalid code")
	}
	if err := h.store.ConfirmTotp(ctx, u.ID); err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.EnrollTotpConfirmResponse{}, nil
}

// VerifyTotp checks a code against the user's CONFIRMED secret. ok=false
// covers wrong code, pending-only enrollment, and no enrollment alike.
func (h *ReadHandler) VerifyTotp(ctx context.Context, req *identityv1.VerifyTotpRequest) (*identityv1.VerifyTotpResponse, error) {
	cipher, err := h.totpCipher()
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "code required")
	}
	cred, err := h.store.GetTotp(ctx, u.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return &identityv1.VerifyTotpResponse{Ok: false}, nil
		}
		return nil, statusFromStoreErr(err)
	}
	if cred.ConfirmedAt == nil {
		return &identityv1.VerifyTotpResponse{Ok: false}, nil
	}
	secret, err := cipher.Open(cred.EncryptedSecret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open totp secret: %v", err)
	}
	return &identityv1.VerifyTotpResponse{Ok: totp.Validate(req.GetCode(), secret)}, nil
}

// --- Email OTP ---

// mfaEmailPurpose validates the request purpose against the closed vocabulary.
func mfaEmailPurpose(p string) (string, error) {
	switch p {
	case store.EmailOTPPurposeLogin, store.EmailOTPPurposeEnroll:
		return p, nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unknown purpose %q", p)
	}
}

// SendEmailOtp mints a single-use 5-minute code for (user, purpose), stores
// only its hash, and emails it. Re-issue inside the cooldown window is
// ResourceExhausted; a user without an email is FailedPrecondition. When the
// send fails the freshly-minted challenge is cancelled so the failure does
// not hold the cooldown against the user.
func (h *ReadHandler) SendEmailOtp(ctx context.Context, req *identityv1.SendEmailOtpRequest) (*identityv1.SendEmailOtpResponse, error) {
	if h.mfa == nil {
		return nil, status.Error(codes.Unavailable, "mfa not configured")
	}
	purpose, err := mfaEmailPurpose(req.GetPurpose())
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if u.Email == "" {
		return nil, status.Error(codes.FailedPrecondition, "user has no email address")
	}
	code, otpID, err := h.store.CreateEmailOTP(ctx, u.ID, purpose)
	if err != nil {
		if errors.Is(err, store.ErrOTPRateLimited) {
			return nil, status.Error(codes.ResourceExhausted, "a code was sent recently; wait before requesting another")
		}
		return nil, statusFromStoreErr(err)
	}
	lg := log.Ctx(ctx)
	if h.mfa.devEcho {
		// Dev ergonomics, mirrors the existing OTP flows. Never enabled in prod.
		lg.Info().Str("purpose", purpose).Str("email", u.Email).Str("otp_code", code).
			Msg("DEV: one-time code (OTP_DEV_ECHO)")
	}
	if h.mfa.sender != nil {
		body := "Use this code to verify your identity on Steward:\n\n    " + code +
			"\n\nThis code expires in 5 minutes and can be used once. If you did not request it, ignore this email."
		if err := h.mfa.sender.Send(ctx, u.Email, "Your verification code", body); err != nil {
			lg.Warn().Err(err).Str("email", u.Email).Msg("mfa otp email send failed")
			if cErr := h.store.CancelEmailOTP(ctx, otpID); cErr != nil {
				lg.Warn().Err(cErr).Msg("cancel undeliverable mfa otp failed")
			}
			return nil, status.Error(codes.Unavailable, "could not send the verification email")
		}
	}
	return &identityv1.SendEmailOtpResponse{}, nil
}

// VerifyEmailOtp verifies an emailed code for (user, purpose). ok=false
// covers wrong/expired/consumed/attempt-locked codes alike (single-use,
// constant-time compare, lockout after repeated wrong guesses — see store).
func (h *ReadHandler) VerifyEmailOtp(ctx context.Context, req *identityv1.VerifyEmailOtpRequest) (*identityv1.VerifyEmailOtpResponse, error) {
	if h.mfa == nil {
		return nil, status.Error(codes.Unavailable, "mfa not configured")
	}
	purpose, err := mfaEmailPurpose(req.GetPurpose())
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "code required")
	}
	if err := h.store.VerifyEmailOTP(ctx, u.ID, purpose, req.GetCode()); err != nil {
		if errors.Is(err, store.ErrOTPInvalid) {
			return &identityv1.VerifyEmailOtpResponse{Ok: false}, nil
		}
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.VerifyEmailOtpResponse{Ok: true}, nil
}

// --- Factor management ---

// ListUserFactors reports the factor kinds the user can currently satisfy:
// "totp" when a confirmed enrollment exists, "passkey" when at least one
// WebAuthn credential is registered, "email" whenever the user has an email
// address (implicit fallback factor).
func (h *ReadHandler) ListUserFactors(ctx context.Context, req *identityv1.ListUserFactorsRequest) (*identityv1.ListUserFactorsResponse, error) {
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	factors := []*identityv1.UserFactor{}
	cred, err := h.store.GetTotp(ctx, u.ID)
	switch {
	case err == nil:
		if cred.ConfirmedAt != nil {
			factors = append(factors, &identityv1.UserFactor{
				Kind:       factorKindTotp,
				EnrolledAt: cred.ConfirmedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
				Label:      cred.Label,
			})
		}
	case errors.Is(err, store.ErrNotFound):
		// no TOTP enrollment — fine
	default:
		return nil, statusFromStoreErr(err)
	}
	passkeys, err := h.store.ListWebauthnCredentials(ctx, u.ID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if len(passkeys) > 0 {
		// Enrolled since the FIRST credential was registered (list is oldest-first).
		factors = append(factors, &identityv1.UserFactor{
			Kind:       factorKindPasskey,
			EnrolledAt: passkeys[0].CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	if u.Email != "" {
		factors = append(factors, &identityv1.UserFactor{Kind: factorKindEmail})
	}
	return &identityv1.ListUserFactorsResponse{Factors: factors}, nil
}

// RemoveFactor deletes the user's credential for the given kind. "totp"
// removes the TOTP enrollment; "passkey" removes ALL of the user's WebAuthn
// credentials (RemoveWebauthnCredential removes a single one); "email" is
// implicit (derived from the user's address) and cannot be removed.
func (h *ReadHandler) RemoveFactor(ctx context.Context, req *identityv1.RemoveFactorRequest) (*identityv1.RemoveFactorResponse, error) {
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	switch req.GetKind() {
	case factorKindTotp:
		if err := h.store.DeleteTotp(ctx, u.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no totp enrollment to remove")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.RemoveFactorResponse{}, nil
	case factorKindEmail:
		return nil, status.Error(codes.FailedPrecondition, "the email factor is implicit and cannot be removed")
	case factorKindPasskey:
		if _, err := h.store.DeleteAllWebauthnCredentials(ctx, u.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no passkeys to remove")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.RemoveFactorResponse{}, nil
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown factor kind %q", req.GetKind())
	}
}

// mfaLabelMaxLen bounds a user-supplied factor label so a runaway value can
// never bloat the row or the factor-management UI.
const mfaLabelMaxLen = 128

// RenameMFAMethod sets the user-facing label on one of the user's enrolled
// second-factor methods, addressed by method_id: the reserved id "totp"
// targets the authenticator factor; any other value is a passkey credential id
// (the id from ListWebauthnCredentials). label "" clears it back to the client
// default. The implicit "email" factor has no stored credential and cannot be
// labelled (FailedPrecondition).
//
// Authz: callers may relabel ONLY their own methods. This RPC operates solely
// on the user_id the (mTLS-authenticated) gateway resolved from the session
// claims — there is no owner id taken from untrusted input — and every store
// write is additionally scoped by user_id, so a method belonging to another
// user is simply invisible (NotFound). Mirrors RemoveFactor /
// RemoveWebauthnCredential.
func (h *ReadHandler) RenameMFAMethod(ctx context.Context, req *identityv1.RenameMFAMethodRequest) (*identityv1.RenameMFAMethodResponse, error) {
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	methodID := req.GetMethodId()
	if methodID == "" {
		return nil, status.Error(codes.InvalidArgument, "method_id required")
	}
	label := req.GetLabel()
	if len(label) > mfaLabelMaxLen {
		return nil, status.Errorf(codes.InvalidArgument, "label too long (max %d characters)", mfaLabelMaxLen)
	}
	switch methodID {
	case factorKindTotp:
		if err := h.store.RenameTotp(ctx, u.ID, label); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no totp enrollment to rename")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.RenameMFAMethodResponse{}, nil
	case factorKindEmail:
		return nil, status.Error(codes.FailedPrecondition, "the email factor is implicit and cannot be labelled")
	default:
		// Any other method id is a passkey credential id.
		if err := h.store.RenameWebauthnCredential(ctx, u.ID, methodID, label); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Error(codes.NotFound, "no such passkey to rename")
			}
			return nil, statusFromStoreErr(err)
		}
		return &identityv1.RenameMFAMethodResponse{}, nil
	}
}

// maskSecret redacts a base32 TOTP secret to a tail hint (last 4 chars) for
// confirmation UI copy. Never log or return the full secret outside the
// otpauth URI itself.
func maskSecret(secret string) string {
	const keep = 4
	if len(secret) <= keep {
		return strings.Repeat("•", len(secret))
	}
	return strings.Repeat("•", 4) + secret[len(secret)-keep:]
}
