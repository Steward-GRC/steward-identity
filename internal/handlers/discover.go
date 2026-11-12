// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"strings"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// Discover implements identifier-first home-realm discovery. An identifier
// with an "@" is treated as an email and resolved by domain; otherwise it is a
// username (= email local-part) looked up to its user's email domain. Unknown
// domains fall through to "local" so we never leak whether a domain is
// configured.
func (h *ReadHandler) Discover(ctx context.Context, req *identityv1.DiscoverRequest) (*identityv1.DiscoverResponse, error) {
	id := strings.TrimSpace(strings.ToLower(req.GetIdentifier()))
	if id == "" {
		return &identityv1.DiscoverResponse{Method: "local"}, nil
	}
	domain := ""
	if at := strings.LastIndex(id, "@"); at >= 0 {
		domain = id[at+1:]
	} else {
		u, err := h.store.GetUserByUsername(ctx, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, statusFromStoreErr(err)
		}
		if err == nil {
			if at := strings.LastIndex(strings.ToLower(u.Email), "@"); at >= 0 {
				domain = strings.ToLower(u.Email)[at+1:]
			}
		}
	}
	if domain == "" {
		return &identityv1.DiscoverResponse{Method: "local"}, nil
	}
	res, err := h.store.DiscoverMethod(ctx, domain)
	if errors.Is(err, store.ErrNotFound) {
		return &identityv1.DiscoverResponse{Method: "local"}, nil
	}
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.DiscoverResponse{
		Method:             res.Method,
		ConnectionAlias:    res.ConnectionAlias,
		IdpInitiatedSsoUrl: res.IdPInitiatedSSOURL,
		//: when the org opted into local fallback, the login gate may
		// offer the local password form even while method=sso.
		AllowLocal: res.AllowLocal,
	}, nil
}

// ResolveLoginEmail turns a username into the email the sign-in service takes
// as its login identifier. Only an enabled, live, local account answers its
// email. Every other case (unknown, disabled, deleted, federated, empty or
// email-shaped input) answers the same empty response with OK, and logs
// nothing, so the answer and the logs never tell which usernames exist. A
// store failure is the only error: it says nothing about the username.
func (h *ReadHandler) ResolveLoginEmail(ctx context.Context, req *identityv1.ResolveLoginEmailRequest) (*identityv1.ResolveLoginEmailResponse, error) {
	// The same normalisation as Discover.
	id := strings.TrimSpace(strings.ToLower(req.GetUsername()))
	if id == "" || strings.Contains(id, "@") {
		return &identityv1.ResolveLoginEmailResponse{}, nil
	}
	u, err := h.store.GetUserByUsername(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return &identityv1.ResolveLoginEmailResponse{}, nil
	}
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if !u.Enabled || u.DeletedAt != nil || !u.LocalAccount {
		return &identityv1.ResolveLoginEmailResponse{}, nil
	}
	return &identityv1.ResolveLoginEmailResponse{Email: u.Email}, nil
}

// CheckBreakGlassEligibility reports whether the account behind req.Email may
// use the audited break-glass local login path when SSO is unavailable. See
// store.BreakGlassLoginEligible for the eligibility rule and reason strings.
func (h *ReadHandler) CheckBreakGlassEligibility(ctx context.Context, req *identityv1.CheckBreakGlassEligibilityRequest) (*identityv1.CheckBreakGlassEligibilityResponse, error) {
	ok, reason, err := h.store.BreakGlassLoginEligible(ctx, req.GetEmail())
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	return &identityv1.CheckBreakGlassEligibilityResponse{Eligible: ok, Reason: reason}, nil
}
