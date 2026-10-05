// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/secrets"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

const mfaTestKey = "6368616e676520746869732070617373776f726420746f206120736563726574"

// failSender always errors — exercises the send-failure path.
type failSender struct{ sent int }

func (f *failSender) Send(_ context.Context, _, _, _ string) error {
	f.sent++
	return errors.New("smtp exploded")
}

// newMFAHandler returns a read handler with the MFA deps wired, plus the
// backing store (for at-rest assertions) and the fake sender.
func newMFAHandler(t *testing.T) (*handlers.ReadHandler, *store.Store, *fakeSender, *secrets.Cipher) {
	t.Helper()
	s := newTestStore(t)
	if s == nil {
		return nil, nil, nil, nil
	}
	cipher, err := secrets.NewFromString(mfaTestKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	sender := &fakeSender{}
	h := handlers.NewReadHandler(s).
		WithMFA(cipher, sender, zerolog.Nop(), false)
	return h, s, sender, cipher
}

func seedUser(t *testing.T, s *store.Store, sub, email string) store.User {
	t.Helper()
	u, err := s.JITProvision(context.Background(), sub, email, "MFA User")
	if err != nil {
		t.Fatalf("JITProvision: %v", err)
	}
	return u
}

// secretFromURI extracts the base32 secret from an otpauth:// URI.
func secretFromURI(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse otpauth uri %q: %v", uri, err)
	}
	sec := u.Query().Get("secret")
	if sec == "" {
		t.Fatalf("otpauth uri missing secret: %q", uri)
	}
	return sec
}

func codeFor(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// --- TOTP ---

func TestTotpEnrollConfirmVerifyHappyPath(t *testing.T) {
	h, s, _, cipher := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-1", "mfa1@example.com")

	begin, err := h.EnrollTotpBegin(ctx, &identityv1.EnrollTotpBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("EnrollTotpBegin: %v", err)
	}
	if !strings.HasPrefix(begin.OtpauthUri, "otpauth://totp/") {
		t.Fatalf("want otpauth://totp/ uri, got %q", begin.OtpauthUri)
	}
	if !strings.Contains(begin.OtpauthUri, "issuer=Steward") {
		t.Fatalf("uri missing issuer=Steward: %q", begin.OtpauthUri)
	}
	if !strings.Contains(begin.OtpauthUri, url.PathEscape("mfa1@example.com")) &&
		!strings.Contains(begin.OtpauthUri, "mfa1@example.com") {
		t.Fatalf("uri missing account email: %q", begin.OtpauthUri)
	}
	secret := secretFromURI(t, begin.OtpauthUri)
	if begin.SecretMasked == "" || strings.Contains(begin.OtpauthUri, begin.SecretMasked) && begin.SecretMasked == secret {
		t.Fatalf("secret_masked must be a redacted hint, got %q", begin.SecretMasked)
	}
	if !strings.HasSuffix(secret, strings.TrimLeft(begin.SecretMasked, "•")) {
		t.Fatalf("secret_masked %q does not match secret tail", begin.SecretMasked)
	}

	// At rest: the stored blob is NOT the plaintext secret, and decrypts to it.
	cred, err := s.GetTotp(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTotp: %v", err)
	}
	if cred.EncryptedSecret == secret || strings.Contains(cred.EncryptedSecret, secret) {
		t.Fatal("TOTP secret stored in plaintext")
	}
	plain, err := cipher.Open(cred.EncryptedSecret)
	if err != nil || plain != secret {
		t.Fatalf("stored secret does not decrypt to the issued one: %v", err)
	}

	// Unconfirmed: not enrolled, verify says no — even with a valid code.
	vr, err := h.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: u.ID.String(), Code: codeFor(t, secret)})
	if err != nil {
		t.Fatalf("VerifyTotp (unconfirmed): %v", err)
	}
	if vr.Ok {
		t.Fatal("unconfirmed TOTP must not verify")
	}
	lf, err := h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserFactors: %v", err)
	}
	for _, f := range lf.Factors {
		if f.Kind == "totp" {
			t.Fatal("unconfirmed TOTP must not be listed as enrolled")
		}
	}

	// Confirm with a valid code → active.
	if _, err := h.EnrollTotpConfirm(ctx, &identityv1.EnrollTotpConfirmRequest{UserId: u.ID.String(), Code: codeFor(t, secret)}); err != nil {
		t.Fatalf("EnrollTotpConfirm: %v", err)
	}
	vr, err = h.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: u.ID.String(), Code: codeFor(t, secret)})
	if err != nil {
		t.Fatalf("VerifyTotp: %v", err)
	}
	if !vr.Ok {
		t.Fatal("confirmed TOTP with valid code must verify")
	}
	lf, err = h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserFactors: %v", err)
	}
	var kinds []string
	for _, f := range lf.Factors {
		kinds = append(kinds, f.Kind)
		if f.Kind == "totp" && f.EnrolledAt == "" {
			t.Fatal("enrolled totp factor missing enrolled_at")
		}
	}
	if !contains(kinds, "totp") || !contains(kinds, "email") {
		t.Fatalf("want totp+email factors, got %v", kinds)
	}

	// Re-begin over a confirmed enrollment is refused.
	if _, err := h.EnrollTotpBegin(ctx, &identityv1.EnrollTotpBeginRequest{UserId: u.ID.String()}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("EnrollTotpBegin over confirmed: want AlreadyExists, got %v", err)
	}
}

func TestTotpConfirmWrongCode(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-2", "mfa2@example.com")

	begin, err := h.EnrollTotpBegin(ctx, &identityv1.EnrollTotpBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("EnrollTotpBegin: %v", err)
	}
	secret := secretFromURI(t, begin.OtpauthUri)
	wrong := "000000"
	if wrong == codeFor(t, secret) {
		wrong = "111111"
	}
	if _, err := h.EnrollTotpConfirm(ctx, &identityv1.EnrollTotpConfirmRequest{UserId: u.ID.String(), Code: wrong}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("confirm with wrong code: want InvalidArgument, got %v", err)
	}
	// Still not enrolled.
	lf, err := h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("ListUserFactors: %v", err)
	}
	for _, f := range lf.Factors {
		if f.Kind == "totp" {
			t.Fatal("failed confirm must not enroll totp")
		}
	}
}

func TestTotpVerifyWrongCodeAndNoEnrollment(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-3", "mfa3@example.com")

	// No enrollment at all → ok=false (not an error; leaks nothing).
	vr, err := h.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: u.ID.String(), Code: "123456"})
	if err != nil {
		t.Fatalf("VerifyTotp (none): %v", err)
	}
	if vr.Ok {
		t.Fatal("verify with no enrollment must be ok=false")
	}

	begin, err := h.EnrollTotpBegin(ctx, &identityv1.EnrollTotpBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("EnrollTotpBegin: %v", err)
	}
	secret := secretFromURI(t, begin.OtpauthUri)
	if _, err := h.EnrollTotpConfirm(ctx, &identityv1.EnrollTotpConfirmRequest{UserId: u.ID.String(), Code: codeFor(t, secret)}); err != nil {
		t.Fatalf("EnrollTotpConfirm: %v", err)
	}
	wrong := "000000"
	if wrong == codeFor(t, secret) {
		wrong = "111111"
	}
	vr, err = h.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: u.ID.String(), Code: wrong})
	if err != nil {
		t.Fatalf("VerifyTotp (wrong): %v", err)
	}
	if vr.Ok {
		t.Fatal("wrong code must not verify")
	}
}

func TestTotpUnavailableWithoutCipher(t *testing.T) {
	s := newTestStore(t)
	u := seedUser(t, s, "kc-mfa-4", "mfa4@example.com")
	h := handlers.NewReadHandler(s) // MFA never wired
	if _, err := h.EnrollTotpBegin(context.Background(), &identityv1.EnrollTotpBeginRequest{UserId: u.ID.String()}); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable without cipher, got %v", err)
	}
}

func TestTotpEnrollUnknownUser(t *testing.T) {
	h, _, _, _ := newMFAHandler(t)
	if _, err := h.EnrollTotpBegin(context.Background(), &identityv1.EnrollTotpBeginRequest{UserId: "b3b25c26-8626-4038-9e5f-000000000001"}); status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound for unknown user, got %v", err)
	}
	if _, err := h.EnrollTotpBegin(context.Background(), &identityv1.EnrollTotpBeginRequest{UserId: "not-a-uuid"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for bad uuid, got %v", err)
	}
}

// --- Email OTP ---

var sixDigits = regexp.MustCompile(`\b(\d{6})\b`)

func sentCode(t *testing.T, sender *fakeSender) string {
	t.Helper()
	m := sixDigits.FindStringSubmatch(sender.body)
	if m == nil {
		t.Fatalf("no 6-digit code in email body %q", sender.body)
	}
	return m[1]
}

func TestEmailOtpSendVerifyHappyPathAndReuse(t *testing.T) {
	h, s, sender, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-5", "mfa5@example.com")

	if _, err := h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "login"}); err != nil {
		t.Fatalf("SendEmailOtp: %v", err)
	}
	if sender.sent != 1 || sender.to != "mfa5@example.com" {
		t.Fatalf("want 1 email to user, got %d to %q", sender.sent, sender.to)
	}
	code := sentCode(t, sender)

	vr, err := h.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: u.ID.String(), Code: code, Purpose: "login"})
	if err != nil {
		t.Fatalf("VerifyEmailOtp: %v", err)
	}
	if !vr.Ok {
		t.Fatal("valid emailed code must verify")
	}
	// Single-use: same code again fails.
	vr, err = h.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: u.ID.String(), Code: code, Purpose: "login"})
	if err != nil {
		t.Fatalf("VerifyEmailOtp (reuse): %v", err)
	}
	if vr.Ok {
		t.Fatal("consumed code must not verify again")
	}
}

func TestEmailOtpWrongCode(t *testing.T) {
	h, s, sender, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-6", "mfa6@example.com")

	if _, err := h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "login"}); err != nil {
		t.Fatalf("SendEmailOtp: %v", err)
	}
	wrong := "000000"
	if wrong == sentCode(t, sender) {
		wrong = "111111"
	}
	vr, err := h.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: u.ID.String(), Code: wrong, Purpose: "login"})
	if err != nil {
		t.Fatalf("VerifyEmailOtp: %v", err)
	}
	if vr.Ok {
		t.Fatal("wrong code must not verify")
	}
}

func TestEmailOtpRateLimit(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-7", "mfa7@example.com")

	if _, err := h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "login"}); err != nil {
		t.Fatalf("SendEmailOtp: %v", err)
	}
	if _, err := h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "login"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("immediate re-send: want ResourceExhausted, got %v", err)
	}
}

func TestEmailOtpValidation(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-8", "mfa8@example.com")
	noEmail := seedUser(t, s, "kc-mfa-9", "")

	// Unknown purpose is rejected up-front.
	if _, err := h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "evil"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad purpose: want InvalidArgument, got %v", err)
	}
	if _, err := h.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: u.ID.String(), Code: "123456", Purpose: "evil"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad purpose on verify: want InvalidArgument, got %v", err)
	}
	// A user without an email cannot receive the factor.
	if _, err := h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: noEmail.ID.String(), Purpose: "login"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("no email: want FailedPrecondition, got %v", err)
	}
}

func TestEmailOtpSendFailureDoesNotHoldCooldown(t *testing.T) {
	s := newTestStore(t)
	cipher, err := secrets.NewFromString(mfaTestKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	fs := &failSender{}
	h := handlers.NewReadHandler(s).WithMFA(cipher, fs, zerolog.Nop(), false)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-10", "mfa10@example.com")

	if _, err := h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "login"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("send failure: want Unavailable, got %v", err)
	}
	// The failed challenge was cancelled — a good sender works immediately.
	ok := &fakeSender{}
	h2 := handlers.NewReadHandler(s).WithMFA(cipher, ok, zerolog.Nop(), false)
	if _, err := h2.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "login"}); err != nil {
		t.Fatalf("send after failed send: %v", err)
	}
}

// --- ListUserFactors / RemoveFactor ---

func TestListFactorsEmailOnly(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	withEmail := seedUser(t, s, "kc-mfa-11", "mfa11@example.com")
	noEmail := seedUser(t, s, "kc-mfa-12", "")

	lf, err := h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: withEmail.ID.String()})
	if err != nil {
		t.Fatalf("ListUserFactors: %v", err)
	}
	if len(lf.Factors) != 1 || lf.Factors[0].Kind != "email" {
		t.Fatalf("want [email], got %+v", lf.Factors)
	}
	lf, err = h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: noEmail.ID.String()})
	if err != nil {
		t.Fatalf("ListUserFactors (no email): %v", err)
	}
	if len(lf.Factors) != 0 {
		t.Fatalf("user without email has no factors, got %+v", lf.Factors)
	}
}

func TestRemoveFactor(t *testing.T) {
	h, s, _, _ := newMFAHandler(t)
	ctx := context.Background()
	u := seedUser(t, s, "kc-mfa-13", "mfa13@example.com")

	begin, err := h.EnrollTotpBegin(ctx, &identityv1.EnrollTotpBeginRequest{UserId: u.ID.String()})
	if err != nil {
		t.Fatalf("EnrollTotpBegin: %v", err)
	}
	secret := secretFromURI(t, begin.OtpauthUri)
	if _, err := h.EnrollTotpConfirm(ctx, &identityv1.EnrollTotpConfirmRequest{UserId: u.ID.String(), Code: codeFor(t, secret)}); err != nil {
		t.Fatalf("EnrollTotpConfirm: %v", err)
	}

	if _, err := h.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: u.ID.String(), Kind: "totp"}); err != nil {
		t.Fatalf("RemoveFactor: %v", err)
	}
	vr, err := h.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: u.ID.String(), Code: codeFor(t, secret)})
	if err != nil {
		t.Fatalf("VerifyTotp after remove: %v", err)
	}
	if vr.Ok {
		t.Fatal("removed TOTP must not verify")
	}
	if _, err := h.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: u.ID.String(), Kind: "totp"}); status.Code(err) != codes.NotFound {
		t.Fatalf("remove again: want NotFound, got %v", err)
	}
	// The implicit email factor cannot be removed; unknown kinds are invalid.
	if _, err := h.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: u.ID.String(), Kind: "email"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove email: want FailedPrecondition, got %v", err)
	}
	if _, err := h.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: u.ID.String(), Kind: "carrier-pigeon"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("remove unknown kind: want InvalidArgument, got %v", err)
	}
}

func contains(ss []string, want string) bool {
	return slices.Contains(ss, want)
}
