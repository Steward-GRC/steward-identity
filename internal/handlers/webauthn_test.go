// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/secrets"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// Test RP config: dev-shaped, matching the service's dev defaults.
const (
	waTestRPID   = "localhost"
	waTestOrigin = "http://localhost:5173"
)

func newTestRP(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          waTestRPID,
		RPDisplayName: "Policy",
		RPOrigins:     []string{waTestOrigin},
	})
	if err != nil {
		t.Fatalf("webauthn.New: %v", err)
	}
	return wa
}

// newWebauthnHandler returns a read handler with MFA + WebAuthn deps wired.
func newWebauthnHandler(t *testing.T) (*handlers.ReadHandler, *store.Store) {
	t.Helper()
	s := newTestStore(t)
	if s == nil {
		return nil, nil
	}
	cipher, err := secrets.NewFromString(mfaTestKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	h := handlers.NewReadHandler(s).
		WithMFA(cipher, &fakeSender{}, zerolog.Nop(), false).
		WithWebauthn(newTestRP(t))
	return h, s
}

// --- virtual authenticator -------------------------------------------------
//
// A minimal software FIDO2 authenticator: ES256 key pair, "none" attestation,
// spec-shaped attestation/assertion payloads. It lets the tests drive the
// FULL server-side ceremony (challenge → attestation verify → credential
// store → assertion verify → sign-count bookkeeping) without a browser.

type virtualAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	origin string
}

func newVirtualAuthenticator(t *testing.T) *virtualAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("credID: %v", err)
	}
	return &virtualAuthenticator{key: key, credID: credID, origin: waTestOrigin}
}

func (a *virtualAuthenticator) credIDb64() string {
	return base64.RawURLEncoding.EncodeToString(a.credID)
}

// cosePublicKey encodes the ES256 public key as a COSE_Key (CTAP2 CBOR).
func (a *virtualAuthenticator) cosePublicKey(t *testing.T) []byte {
	t.Helper()
	b, err := webauthncbor.Marshal(map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: a.key.X.FillBytes(make([]byte, 32)),
		-3: a.key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("cose key: %v", err)
	}
	return b
}

// challengeFromOptions pulls publicKey.challenge (base64url) out of the
// opaque options JSON a Begin RPC returned.
func challengeFromOptions(t *testing.T, optionsJSON string) string {
	t.Helper()
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(optionsJSON), &opts); err != nil {
		t.Fatalf("parse options json: %v", err)
	}
	if opts.PublicKey.Challenge == "" {
		t.Fatalf("options json missing publicKey.challenge: %s", optionsJSON)
	}
	return opts.PublicKey.Challenge
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// register produces the browser's attestation-response JSON for the given
// creation options ("none" attestation, flags UP|UV|AT, counter 0).
func (a *virtualAuthenticator) register(t *testing.T, optionsJSON string) string {
	t.Helper()
	challenge := challengeFromOptions(t, optionsJSON)
	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.create",
		"challenge": challenge,
		"origin":    a.origin,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	rpHash := sha256.Sum256([]byte(waTestRPID))
	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(0x45)                                             // UP | UV | AT
	_ = binary.Write(&authData, binary.BigEndian, uint32(0))             // sign count
	authData.Write(make([]byte, 16))                                     // AAGUID
	_ = binary.Write(&authData, binary.BigEndian, uint16(len(a.credID))) //nolint:gosec
	authData.Write(a.credID)
	authData.Write(a.cosePublicKey(t))

	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData.Bytes(),
	})
	if err != nil {
		t.Fatalf("attestation object: %v", err)
	}

	resp, err := json.Marshal(map[string]any{
		"id":    a.credIDb64(),
		"rawId": a.credIDb64(),
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": b64u(attObj),
			"clientDataJSON":    b64u(clientData),
			"transports":        []string{"usb"},
		},
	})
	if err != nil {
		t.Fatalf("registration response: %v", err)
	}
	return string(resp)
}

// assert produces the browser's assertion-response JSON for the given request
// options, signing with the authenticator's key at the given counter value.
func (a *virtualAuthenticator) assert(t *testing.T, optionsJSON string, counter uint32, userHandle []byte) string {
	t.Helper()
	challenge := challengeFromOptions(t, optionsJSON)
	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.get",
		"challenge": challenge,
		"origin":    a.origin,
	})
	if err != nil {
		t.Fatalf("client data: %v", err)
	}

	rpHash := sha256.Sum256([]byte(waTestRPID))
	var authData bytes.Buffer
	authData.Write(rpHash[:])
	authData.WriteByte(0x05) // UP | UV
	_ = binary.Write(&authData, binary.BigEndian, counter)

	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(authData.Bytes(), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	resp, err := json.Marshal(map[string]any{
		"id":    a.credIDb64(),
		"rawId": a.credIDb64(),
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": b64u(authData.Bytes()),
			"clientDataJSON":    b64u(clientData),
			"signature":         b64u(sig),
			"userHandle":        b64u(userHandle),
		},
	})
	if err != nil {
		t.Fatalf("assertion response: %v", err)
	}
	return string(resp)
}

// enrollPasskey drives a full registration ceremony.
func enrollPasskey(t *testing.T, h *handlers.ReadHandler, a *virtualAuthenticator, userID, label string) {
	t.Helper()
	ctx := context.Background()
	begin, err := h.WebauthnRegisterBegin(ctx, &identityv1.WebauthnRegisterBeginRequest{UserId: userID})
	if err != nil {
		t.Fatalf("WebauthnRegisterBegin: %v", err)
	}
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId:         userID,
		SessionId:      begin.SessionId,
		CredentialJson: a.register(t, begin.OptionsJson),
		Label:          label,
	}); err != nil {
		t.Fatalf("WebauthnRegisterFinish: %v", err)
	}
}

// assertOnce drives a full assertion ceremony and returns ok.
func assertOnce(t *testing.T, h *handlers.ReadHandler, a *virtualAuthenticator, u store.User, counter uint32) bool {
	t.Helper()
	ctx := context.Background()
	begin, err := h.WebauthnAssertBegin(ctx, &identityv1.WebauthnAssertBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("WebauthnAssertBegin: %v", err)
	}
	uid := u.ID
	fin, err := h.WebauthnAssertFinish(ctx, &identityv1.WebauthnAssertFinishRequest{
		UserId:         u.ID.String(),
		SessionId:      begin.SessionId,
		CredentialJson: a.assert(t, begin.OptionsJson, counter, uid[:]),
	})
	if err != nil {
		t.Fatalf("WebauthnAssertFinish: %v", err)
	}
	return fin.Ok
}

// --- tests -------------------------------------------------------------

func TestWebauthnRegisterAndAssertHappyPath(t *testing.T) {
	h, s := newWebauthnHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-wa-h1", "wah1@example.com")
	auth := newVirtualAuthenticator(t)

	begin, err := h.WebauthnRegisterBegin(ctx, &identityv1.WebauthnRegisterBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("WebauthnRegisterBegin: %v", err)
	}
	if !strings.Contains(begin.OptionsJson, `"rp"`) || !strings.Contains(begin.OptionsJson, waTestRPID) {
		t.Fatalf("options json missing rp info: %s", begin.OptionsJson)
	}
	challengeFromOptions(t, begin.OptionsJson) // asserts a challenge exists

	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId:         u.ID.String(),
		SessionId:      begin.SessionId,
		CredentialJson: auth.register(t, begin.OptionsJson),
		Label:          "YubiKey 5",
	}); err != nil {
		t.Fatalf("WebauthnRegisterFinish: %v", err)
	}

	// Factor list now reports passkey.
	lf, err := h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserFactors: %v", err)
	}
	var passkey *identityv1.UserFactor
	for _, f := range lf.Factors {
		if f.Kind == "passkey" {
			passkey = f
		}
	}
	if passkey == nil {
		t.Fatalf("want passkey factor after registration, got %+v", lf.Factors)
	}
	if passkey.EnrolledAt == "" {
		t.Fatal("passkey factor missing enrolled_at")
	}

	// Credential list round-trip.
	lc, err := h.ListWebauthnCredentials(ctx, &identityv1.ListWebauthnCredentialsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListWebauthnCredentials: %v", err)
	}
	if len(lc.Credentials) != 1 {
		t.Fatalf("want 1 credential, got %d", len(lc.Credentials))
	}
	c := lc.Credentials[0]
	if c.Id != auth.credIDb64() || c.Label != "YubiKey 5" || c.CreatedAt == "" {
		t.Fatalf("credential mismatch: %+v", c)
	}
	if len(c.Transports) != 1 || c.Transports[0] != "usb" {
		t.Fatalf("transports mismatch: %v", c.Transports)
	}
	if c.LastUsedAt != "" {
		t.Fatal("fresh credential must have empty last_used_at")
	}

	// Assert with an advancing counter succeeds and stamps usage.
	if !assertOnce(t, h, auth, u, 1) {
		t.Fatal("valid assertion must verify")
	}
	lc, err = h.ListWebauthnCredentials(ctx, &identityv1.ListWebauthnCredentialsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListWebauthnCredentials: %v", err)
	}
	if lc.Credentials[0].LastUsedAt == "" {
		t.Fatal("last_used_at must be stamped after a successful assertion")
	}
}

func TestWebauthnRegisterSessionSingleUse(t *testing.T) {
	h, s := newWebauthnHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-wa-h2", "wah2@example.com")
	auth := newVirtualAuthenticator(t)

	begin, err := h.WebauthnRegisterBegin(ctx, &identityv1.WebauthnRegisterBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("WebauthnRegisterBegin: %v", err)
	}
	// Garbage credential burns the session (single-use even on failure)...
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId: u.ID.String(), SessionId: begin.SessionId, CredentialJson: `{"garbage":`,
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("garbage credential: want InvalidArgument, got %v", err)
	}
	// ...so a valid response against the same session is refused.
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId: u.ID.String(), SessionId: begin.SessionId,
		CredentialJson: auth.register(t, begin.OptionsJson),
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("burned session: want NotFound, got %v", err)
	}
	// Bad session ids.
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId: u.ID.String(), SessionId: "not-a-uuid", CredentialJson: "{}",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad session id: want InvalidArgument, got %v", err)
	}
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId: u.ID.String(), SessionId: "b3b25c26-8626-4038-9e5f-000000000002", CredentialJson: "{}",
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown session: want NotFound, got %v", err)
	}
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId: u.ID.String(), SessionId: begin.SessionId, CredentialJson: "",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty credential: want InvalidArgument, got %v", err)
	}
}

func TestWebauthnRegisterWrongOrigin(t *testing.T) {
	h, s := newWebauthnHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-wa-h3", "wah3@example.com")
	auth := newVirtualAuthenticator(t)
	auth.origin = "https://evil.example.com" // not in the RP's origin allow-list

	begin, err := h.WebauthnRegisterBegin(ctx, &identityv1.WebauthnRegisterBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("WebauthnRegisterBegin: %v", err)
	}
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId: u.ID.String(), SessionId: begin.SessionId,
		CredentialJson: auth.register(t, begin.OptionsJson),
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong origin: want InvalidArgument, got %v", err)
	}
	// Nothing was stored.
	lc, err := h.ListWebauthnCredentials(ctx, &identityv1.ListWebauthnCredentialsRequest{UserId: u.ID.String()})
	if err != nil || len(lc.Credentials) != 0 {
		t.Fatalf("no credential must be stored after failed verify: %d, %v", len(lc.Credentials), err)
	}
}

func TestWebauthnRegisterDuplicateCredential(t *testing.T) {
	h, s := newWebauthnHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-wa-h4", "wah4@example.com")
	auth := newVirtualAuthenticator(t)
	enrollPasskey(t, h, auth, u.ID.String(), "first")

	// The restart ceremony's options carry the exclude list.
	begin, err := h.WebauthnRegisterBegin(ctx, &identityv1.WebauthnRegisterBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("WebauthnRegisterBegin #2: %v", err)
	}
	if !strings.Contains(begin.OptionsJson, "excludeCredentials") ||
		!strings.Contains(begin.OptionsJson, auth.credIDb64()) {
		t.Fatalf("second-begin options missing exclude list: %s", begin.OptionsJson)
	}
	// A client that ignores the exclude list is stopped server-side.
	if _, err := h.WebauthnRegisterFinish(ctx, &identityv1.WebauthnRegisterFinishRequest{
		UserId: u.ID.String(), SessionId: begin.SessionId,
		CredentialJson: auth.register(t, begin.OptionsJson),
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate credential: want AlreadyExists, got %v", err)
	}
}

func TestWebauthnAssertSignCountRegression(t *testing.T) {
	h, s := newWebauthnHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-wa-h5", "wah5@example.com")
	auth := newVirtualAuthenticator(t)
	enrollPasskey(t, h, auth, u.ID.String(), "counter key")

	if !assertOnce(t, h, auth, u, 5) {
		t.Fatal("assertion with counter 5 must verify")
	}
	// Same counter again: regression → rejected (possible clone).
	if assertOnce(t, h, auth, u, 5) {
		t.Fatal("assertion with a NON-advancing counter must be rejected")
	}
	// Lower counter: regression → rejected.
	if assertOnce(t, h, auth, u, 3) {
		t.Fatal("assertion with a regressed counter must be rejected")
	}
	// The stored counter was not advanced by the rejected attempts: a proper
	// successor still verifies.
	if !assertOnce(t, h, auth, u, 6) {
		t.Fatal("assertion with an advancing counter must verify after rejections")
	}
	// Stored sign count follows the last SUCCESSFUL assertion.
	creds, err := s.ListWebauthnCredentials(ctx, u.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("list stored: %v", err)
	}
	if creds[0].SignCount != 6 {
		t.Fatalf("stored sign_count: want 6, got %d", creds[0].SignCount)
	}
}

func TestWebauthnAssertForgedSignature(t *testing.T) {
	h, s := newWebauthnHandler(t)
	u := seedUser(t, s, "kc-wa-h6", "wah6@example.com")
	auth := newVirtualAuthenticator(t)
	enrollPasskey(t, h, auth, u.ID.String(), "real key")

	// An impostor with the right credential ID but the WRONG private key.
	forger := newVirtualAuthenticator(t)
	forger.credID = auth.credID
	if assertOnce(t, h, forger, u, 1) {
		t.Fatal("assertion signed by the wrong key must be rejected")
	}
}

func TestWebauthnAssertNoCredentials(t *testing.T) {
	h, s := newWebauthnHandler(t)
	u := seedUser(t, s, "kc-wa-h7", "wah7@example.com")
	if _, err := h.WebauthnAssertBegin(context.Background(), &identityv1.WebauthnAssertBeginRequest{UserId: u.ID.String()}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("assert begin with no passkeys: want FailedPrecondition, got %v", err)
	}
}

func TestWebauthnUnavailableWithoutRP(t *testing.T) {
	s := newTestStore(t)
	u := seedUser(t, s, "kc-wa-h8", "wah8@example.com")
	h := handlers.NewReadHandler(s) // WebAuthn never wired
	ctx := context.Background()

	if _, err := h.WebauthnRegisterBegin(ctx, &identityv1.WebauthnRegisterBeginRequest{UserId: u.ID.String()}); status.Code(err) != codes.Unavailable {
		t.Fatalf("register begin without RP: want Unavailable, got %v", err)
	}
	if _, err := h.WebauthnAssertBegin(ctx, &identityv1.WebauthnAssertBeginRequest{UserId: u.ID.String()}); status.Code(err) != codes.Unavailable {
		t.Fatalf("assert begin without RP: want Unavailable, got %v", err)
	}
	// Credential management is a plain store surface — still available.
	if lc, err := h.ListWebauthnCredentials(ctx, &identityv1.ListWebauthnCredentialsRequest{UserId: u.ID.String()}); err != nil || len(lc.Credentials) != 0 {
		t.Fatalf("list without RP: %v", err)
	}
	if _, err := h.RemoveWebauthnCredential(ctx, &identityv1.RemoveWebauthnCredentialRequest{UserId: u.ID.String(), CredentialId: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("remove without RP: want NotFound, got %v", err)
	}
}

func TestWebauthnRemoveCredentialAndFactor(t *testing.T) {
	h, s := newWebauthnHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-wa-h9", "wah9@example.com")
	key1 := newVirtualAuthenticator(t)
	key2 := newVirtualAuthenticator(t)
	enrollPasskey(t, h, key1, u.ID.String(), "key one")
	enrollPasskey(t, h, key2, u.ID.String(), "key two")

	// Individual removal.
	if _, err := h.RemoveWebauthnCredential(ctx, &identityv1.RemoveWebauthnCredentialRequest{
		UserId: u.ID.String(), CredentialId: key1.credIDb64(),
	}); err != nil {
		t.Fatalf("RemoveWebauthnCredential: %v", err)
	}
	lc, err := h.ListWebauthnCredentials(ctx, &identityv1.ListWebauthnCredentialsRequest{UserId: u.ID.String()})
	if err != nil || len(lc.Credentials) != 1 || lc.Credentials[0].Label != "key two" {
		t.Fatalf("after single removal: %+v, %v", lc.Credentials, err)
	}
	if _, err := h.RemoveWebauthnCredential(ctx, &identityv1.RemoveWebauthnCredentialRequest{
		UserId: u.ID.String(), CredentialId: key1.credIDb64(),
	}); status.Code(err) != codes.NotFound {
		t.Fatalf("re-remove: want NotFound, got %v", err)
	}
	if _, err := h.RemoveWebauthnCredential(ctx, &identityv1.RemoveWebauthnCredentialRequest{
		UserId: u.ID.String(), CredentialId: "",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty credential_id: want InvalidArgument, got %v", err)
	}

	// RemoveFactor(passkey) sweeps the rest.
	if _, err := h.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: u.ID.String(), Kind: "passkey"}); err != nil {
		t.Fatalf("RemoveFactor(passkey): %v", err)
	}
	lf, err := h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserFactors: %v", err)
	}
	for _, f := range lf.Factors {
		if f.Kind == "passkey" {
			t.Fatal("passkey factor must disappear after RemoveFactor")
		}
	}
	if _, err := h.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: u.ID.String(), Kind: "passkey"}); status.Code(err) != codes.NotFound {
		t.Fatalf("RemoveFactor(passkey) again: want NotFound, got %v", err)
	}
}
