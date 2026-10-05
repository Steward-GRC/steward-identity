// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
)

// TestSSOPublicEdge_FreshJITUser_EmailOtpTargetAndOnboardingGate locks the
// identity-side contract the fix depends on: a fresh public-edge SSO
// login (JIT-provisioned federated user — email set from the assertion, NO
// strong factor, NOT yet onboarded, the state a new SSO user is in) must
//
//  1. be a valid email-OTP target on the account's SSO-verified email with NO
//     separate enrollment ceremony (email is an implicit factor), so the gateway
//     can challenge it, AND
//  2. still be forced through name+terms onboarding afterwards — satisfying the
//     MFA factor does NOT clear the onboarding gate.
//
// Both gates must hold before the account is fully onboarded.
func TestSSOPublicEdge_FreshJITUser_EmailOtpTargetAndOnboardingGate(t *testing.T) {
	h, s, sender, _ := newMFAHandler(t)
	ctx := context.Background()

	// A first-seen federated user as the SSO callback JIT-provisions one: email
	// from the IdP assertion, no display names yet, and — by the migration default
	// — onboarding_complete=false.
	u, err := s.JITProvision(ctx, "kc-sso-59", "jit59@example.org", "")
	require.NoError(t, err)
	require.False(t, u.OnboardingComplete, "a fresh JIT user must start un-onboarded")

	// The ONLY factor is the implicit email — no TOTP/passkey. This is the
	// no-strong-factor state the gateway now challenges with an email OTP.
	lf, err := h.ListUserFactors(ctx, &identityv1.ListUserFactorsRequest{UserId: u.ID.String()})
	require.NoError(t, err)
	require.Len(t, lf.GetFactors(), 1)
	require.Equal(t, "email", lf.GetFactors()[0].GetKind())

	// SendEmailOtp(login) targets the account's SSO-verified email with NO enrolled
	// email-OTP factor required — the assertion proved ownership of the address.
	_, err = h.SendEmailOtp(ctx, &identityv1.SendEmailOtpRequest{UserId: u.ID.String(), Purpose: "login"})
	require.NoError(t, err)
	require.Equal(t, 1, sender.sent)
	require.Equal(t, "jit59@example.org", sender.to, "the login OTP goes to the account's SSO-verified email")

	// The emailed login code verifies — this is exactly what the gateway's
	// /auth/mfa/verify promotes a session on.
	vr, err := h.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{
		UserId: u.ID.String(), Code: sentCode(t, sender), Purpose: "login",
	})
	require.NoError(t, err)
	require.True(t, vr.GetOk(), "the emailed login OTP must verify for an SSO user")

	// Satisfying MFA does NOT satisfy onboarding: the user is still needs_onboarding
	// (the SPA gate keeps them pinned on /welcome until name+terms are provided).
	before, err := h.GetUser(ctx, &identityv1.GetUserRequest{UserId: u.ID.String()})
	require.NoError(t, err)
	require.True(t, before.GetUser().GetNeedsOnboarding(), "MFA alone must not clear the onboarding gate")

	// Completing name + terms is what flips the gate — the second required step.
	admin := handlers.NewAdminHandler(s, testAdminAuth())
	done, err := admin.CompleteOnboarding(claimsCtx(u.ID.String(), nil), &identityv1.CompleteOnboardingRequest{
		AcceptTerms: true, FirstName: new("Jit"), LastName: new("Fiftynine"),
	})
	require.NoError(t, err)
	require.False(t, done.GetUser().GetNeedsOnboarding(), "name+terms completes onboarding")
	require.Equal(t, "Jit", done.GetUser().GetFirstName())
	require.Equal(t, "Fiftynine", done.GetUser().GetLastName())
}
