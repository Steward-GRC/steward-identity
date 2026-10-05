// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Bugs5382/go-log"
	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/safecast"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MFA second factors: WebAuthn/FIDO2
// passkeys — browser/platform passkeys, hardware security keys and platform
// biometrics are all WebAuthn authenticators against the same relying party.
// Identity is the RP (go-webauthn); the BFF passes the opaque options /
// credential JSON between these RPCs and the browser widget verbatim.
//
// Ceremony shape: Begin creates the challenge and persists the go-webauthn
// SessionData server-side (webauthn_sessions, ~5 min TTL); Finish redeems the
// session EXACTLY ONCE (deleted whether or not verification succeeds) and
// verifies the authenticator's response against it. Only PUBLIC key material
// is ever stored.

// webauthnLabelMaxLen caps the user-facing credential label.
const webauthnLabelMaxLen = 120

// WithWebauthn wires the go-webauthn relying party onto the read handler.
// wa=nil leaves the passkey ceremony RPCs returning Unavailable (no
// WEBAUTHN_RP_* config) while credential listing/removal — plain store reads
// — keep working.
func (h *ReadHandler) WithWebauthn(wa *webauthn.WebAuthn) *ReadHandler {
	h.webauthn = wa
	return h
}

// webauthnRP returns the relying party or Unavailable when passkeys are not
// configured (mirrors the TOTP_ENC_KEY nil-deps pattern).
func (h *ReadHandler) webauthnRP() (*webauthn.WebAuthn, error) {
	if h.webauthn == nil {
		return nil, status.Error(codes.Unavailable, "passkeys not configured")
	}
	return h.webauthn, nil
}

// webauthnUser adapts an identity user + their stored credentials to the
// webauthn.User interface. The user handle is the raw platform user-id UUID
// (16 opaque bytes, stable for the account's lifetime).
type webauthnUser struct {
	user  store.User
	creds []webauthn.Credential
}

func (w *webauthnUser) WebAuthnID() []byte {
	id := w.user.ID
	return id[:]
}

func (w *webauthnUser) WebAuthnName() string {
	switch {
	case w.user.Email != "":
		return w.user.Email
	case w.user.Username != "":
		return w.user.Username
	default:
		return w.user.ID.String()
	}
}

func (w *webauthnUser) WebAuthnDisplayName() string {
	if w.user.Name != "" {
		return w.user.Name
	}
	return w.WebAuthnName()
}

func (w *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// credentialFromStore rehydrates a stored row into the go-webauthn credential
// the library verifies assertions against.
func credentialFromStore(c store.WebauthnCredential) (webauthn.Credential, error) {
	id, err := base64.RawURLEncoding.DecodeString(c.CredentialID)
	if err != nil {
		return webauthn.Credential{}, err
	}
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
	for _, tr := range c.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(tr))
	}
	return webauthn.Credential{
		ID:        id,
		PublicKey: c.PublicKey,
		Transport: transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: safecast.Uint32FromInt64(c.SignCount),
		},
	}, nil
}

// webauthnUserFor loads the user's stored credentials and wraps both in the
// webauthn.User adapter.
func (h *ReadHandler) webauthnUserFor(ctx context.Context, u store.User) (*webauthnUser, []store.WebauthnCredential, error) {
	stored, err := h.store.ListWebauthnCredentials(ctx, u.ID)
	if err != nil {
		return nil, nil, statusFromStoreErr(err)
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		wc, err := credentialFromStore(c)
		if err != nil {
			return nil, nil, status.Errorf(codes.Internal, "decode stored credential id: %v", err)
		}
		creds = append(creds, wc)
	}
	return &webauthnUser{user: u, creds: creds}, stored, nil
}

// signCountRegressed reports whether an assertion's authenticator counter
// indicates a possibly cloned authenticator (WebAuthn §6.1.1): whenever the
// stored count or the new count is non-zero, the new count must STRICTLY
// exceed the stored one. Both zero means the authenticator does not implement
// a counter — allowed.
func signCountRegressed(stored, latest uint32) bool {
	if stored == 0 && latest == 0 {
		return false
	}
	return latest <= stored
}

// beginSession marshals the go-webauthn SessionData and opens the single-use
// server-side challenge session for it.
func (h *ReadHandler) beginSession(ctx context.Context, userID store.User, purpose string, session *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", status.Errorf(codes.Internal, "marshal webauthn session: %v", err)
	}
	id, err := h.store.CreateWebauthnSession(ctx, userID.ID, purpose, string(data))
	if err != nil {
		return "", statusFromStoreErr(err)
	}
	return id.String(), nil
}

// consumeSession redeems the challenge session (single-use) and unmarshals
// the go-webauthn SessionData. Unknown/expired/already-used sessions are
// NotFound — the widget must restart the ceremony.
func (h *ReadHandler) consumeSession(ctx context.Context, sessionID string, u store.User, purpose string) (webauthn.SessionData, error) {
	var session webauthn.SessionData
	sid, err := parseUUID(sessionID, "session_id")
	if err != nil {
		return session, err
	}
	data, err := h.store.ConsumeWebauthnSession(ctx, sid, u.ID, purpose)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return session, status.Errorf(codes.NotFound, "no pending %s ceremony for this session (expired, used, or unknown) — begin again", purpose)
		}
		return session, statusFromStoreErr(err)
	}
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return session, status.Errorf(codes.Internal, "decode webauthn session: %v", err)
	}
	return session, nil
}

// --- Registration ceremony ---

// WebauthnRegisterBegin starts a credential-registration ceremony: mints the
// challenge, persists the session server-side, and returns the (opaque)
// creation options for navigator.credentials.create(). Already-registered
// credentials ride along as an exclude list so the same authenticator cannot
// be enrolled twice.
func (h *ReadHandler) WebauthnRegisterBegin(ctx context.Context, req *identityv1.WebauthnRegisterBeginRequest) (*identityv1.WebauthnRegisterBeginResponse, error) {
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	wa, err := h.webauthnRP()
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	wu, _, err := h.webauthnUserFor(ctx, u)
	if err != nil {
		return nil, err
	}
	var opts []webauthn.RegistrationOption
	if len(wu.creds) > 0 {
		exclusions := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
		for _, c := range wu.creds {
			exclusions = append(exclusions, c.Descriptor())
		}
		opts = append(opts, webauthn.WithExclusions(exclusions))
	}
	creation, session, err := wa.BeginRegistration(wu, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "begin registration: %v", err)
	}
	sessionID, err := h.beginSession(ctx, u, store.WebauthnPurposeRegister, session)
	if err != nil {
		return nil, err
	}
	optionsJSON, err := json.Marshal(creation)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal creation options: %v", err)
	}
	return &identityv1.WebauthnRegisterBeginResponse{
		OptionsJson: string(optionsJSON),
		SessionId:   sessionID,
	}, nil
}

// WebauthnRegisterFinish verifies the authenticator's attestation response
// against the pending (single-use) session and stores the new credential.
// Malformed or unverifiable responses are InvalidArgument; the session is
// consumed either way. A credential id that already exists is AlreadyExists.
func (h *ReadHandler) WebauthnRegisterFinish(ctx context.Context, req *identityv1.WebauthnRegisterFinishRequest) (*identityv1.WebauthnRegisterFinishResponse, error) {
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	wa, err := h.webauthnRP()
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetCredentialJson() == "" {
		return nil, status.Error(codes.InvalidArgument, "credential_json required")
	}
	session, err := h.consumeSession(ctx, req.GetSessionId(), u, store.WebauthnPurposeRegister)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes([]byte(req.GetCredentialJson()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed webauthn credential")
	}
	wu, _, err := h.webauthnUserFor(ctx, u)
	if err != nil {
		return nil, err
	}
	cred, err := wa.CreateCredential(wu, session, parsed)
	if err != nil {
		lg := logger.Ctx(ctx)
		lg.Warn("webauthn registration verification failed", log.F("user_id", u.ID.String()), log.F("error", errText(err)))
		return nil, status.Error(codes.InvalidArgument, "credential verification failed")
	}
	label := strings.TrimSpace(req.GetLabel())
	if len(label) > webauthnLabelMaxLen {
		label = label[:webauthnLabelMaxLen]
	}
	transports := make([]string, 0, len(cred.Transport))
	for _, tr := range cred.Transport {
		transports = append(transports, string(tr))
	}
	if err := h.store.InsertWebauthnCredential(ctx, store.WebauthnCredential{
		CredentialID:   base64.RawURLEncoding.EncodeToString(cred.ID),
		UserID:         u.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      int64(cred.Authenticator.SignCount),
		AAGUID:         cred.Authenticator.AAGUID,
		Transports:     transports,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		Label:          label,
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, status.Error(codes.AlreadyExists, "credential already registered")
		}
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.WebauthnRegisterFinishResponse{}, nil
}

// --- Assertion ceremony ---

// WebauthnAssertBegin starts an assertion (login) ceremony scoped to the
// user's registered credentials. A user with no passkeys is
// FailedPrecondition (the BFF should offer a different factor).
func (h *ReadHandler) WebauthnAssertBegin(ctx context.Context, req *identityv1.WebauthnAssertBeginRequest) (*identityv1.WebauthnAssertBeginResponse, error) {
	wa, err := h.webauthnRP()
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	wu, _, err := h.webauthnUserFor(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(wu.creds) == 0 {
		return nil, status.Error(codes.FailedPrecondition, "no passkeys enrolled")
	}
	// Apply the same user-verification requirement as registration (the RP
	// config carries it) so login is explicit, not the library default.
	uv := wa.Config.AuthenticatorSelection.UserVerification
	if uv == "" {
		uv = protocol.VerificationPreferred
	}
	assertion, session, err := wa.BeginLogin(wu, webauthn.WithUserVerification(uv))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "begin assertion: %v", err)
	}
	sessionID, err := h.beginSession(ctx, u, store.WebauthnPurposeAssert, session)
	if err != nil {
		return nil, err
	}
	optionsJSON, err := json.Marshal(assertion)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal assertion options: %v", err)
	}
	return &identityv1.WebauthnAssertBeginResponse{
		OptionsJson: string(optionsJSON),
		SessionId:   sessionID,
	}, nil
}

// WebauthnAssertFinish verifies the authenticator's assertion against the
// pending (single-use) session. ok=false covers signature/verification
// failures AND a sign-count regression (possible cloned authenticator —
// logged, counter NOT advanced) alike, leaking nothing about which. On
// success the credential's sign count and last_used_at are updated.
func (h *ReadHandler) WebauthnAssertFinish(ctx context.Context, req *identityv1.WebauthnAssertFinishRequest) (*identityv1.WebauthnAssertFinishResponse, error) {
	wa, err := h.webauthnRP()
	if err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetCredentialJson() == "" {
		return nil, status.Error(codes.InvalidArgument, "credential_json required")
	}
	session, err := h.consumeSession(ctx, req.GetSessionId(), u, store.WebauthnPurposeAssert)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(req.GetCredentialJson()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed webauthn assertion")
	}
	wu, stored, err := h.webauthnUserFor(ctx, u)
	if err != nil {
		return nil, err
	}
	lg := logger.Ctx(ctx)
	cred, err := wa.ValidateLogin(wu, session, parsed)
	if err != nil {
		lg.Info("webauthn assertion verification failed", log.F("user_id", u.ID.String()), log.F("error", errText(err)))
		return &identityv1.WebauthnAssertFinishResponse{Ok: false}, nil
	}

	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	var storedCount uint32
	for _, c := range stored {
		if c.CredentialID == credID {
			storedCount = safecast.Uint32FromInt64(c.SignCount)
			break
		}
	}
	newCount := parsed.Response.AuthenticatorData.Counter
	// Sign-count regression = possible cloned authenticator (the private key
	// may exist in more than one place). Reject the assertion and flag it; the
	// stored counter is deliberately NOT advanced. go-webauthn surfaces the
	// same condition as CloneWarning — checked too, belt and braces.
	if signCountRegressed(storedCount, newCount) || cred.Authenticator.CloneWarning {
		lg.Warn("webauthn sign-count regression — possible cloned authenticator; assertion rejected", log.F("user_id", u.ID.String()), log.F("credential_id", credID), log.F("stored_sign_count", storedCount), log.F("assertion_sign_count", newCount))
		return &identityv1.WebauthnAssertFinishResponse{Ok: false}, nil
	}
	if err := h.store.UpdateWebauthnCredentialUsage(ctx, u.ID, credID, int64(newCount)); err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.WebauthnAssertFinishResponse{Ok: true}, nil
}

// --- Credential management ---

// ListWebauthnCredentials lists the user's registered passkeys for the
// factor-management surface. Works without RP config (plain store read).
func (h *ReadHandler) ListWebauthnCredentials(ctx context.Context, req *identityv1.ListWebauthnCredentialsRequest) (*identityv1.ListWebauthnCredentialsResponse, error) {
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	stored, err := h.store.ListWebauthnCredentials(ctx, u.ID)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := make([]*identityv1.WebauthnCredential, 0, len(stored))
	for _, c := range stored {
		pc := &identityv1.WebauthnCredential{
			Id:         c.CredentialID,
			Label:      c.Label,
			CreatedAt:  c.CreatedAt.UTC().Format(time.RFC3339),
			Transports: append([]string{}, c.Transports...),
		}
		if c.LastUsedAt != nil {
			pc.LastUsedAt = c.LastUsedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, pc)
	}
	return &identityv1.ListWebauthnCredentialsResponse{Credentials: out}, nil
}

// RemoveWebauthnCredential deletes a single passkey by credential id.
// NotFound when the user has no such credential.
func (h *ReadHandler) RemoveWebauthnCredential(ctx context.Context, req *identityv1.RemoveWebauthnCredentialRequest) (*identityv1.RemoveWebauthnCredentialResponse, error) {
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	u, err := h.mfaUser(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	if req.GetCredentialId() == "" {
		return nil, status.Error(codes.InvalidArgument, "credential_id required")
	}
	if err := h.store.DeleteWebauthnCredential(ctx, u.ID, req.GetCredentialId()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "no such credential")
		}
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.RemoveWebauthnCredentialResponse{}, nil
}
