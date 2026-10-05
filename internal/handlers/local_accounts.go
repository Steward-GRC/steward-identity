// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errUsernameIsEmail refuses an email as a username: a browser's autofill
// would otherwise set the sign-in name to the email without the user
// noticing. Enforced wherever a new username enters.
var errUsernameIsEmail = status.Error(codes.InvalidArgument, "username must be a plain username, not an email address")

// usernameLooksLikeEmail reports whether s is being used as an email address.
func usernameLooksLikeEmail(s string) bool { return strings.Contains(s, "@") }

// localAccounts is the Kratos surface local accounts need. Nil answers
// LOCAL_ACCOUNTS_UNAVAILABLE.
type localAccounts interface {
	signInService
	DeleteIdentity(ctx context.Context, identityID string) error
}

func (h *AdminHandler) requireLocalAccounts(ctx context.Context) error {
	if h.accounts == nil {
		return errcodes.Error(ctx, errcodes.LocalAccountsUnavailable())
	}
	return nil
}

// CreateLocalUser creates a local account: a Kratos identity with the
// password, then the platform row (local_account, no external subject yet;
// the first sign-in links it). The email and the uniqueness of the username
// and email are checked before anything is created, and a row that can't be
// written rolls the Kratos identity back.
func (h *AdminHandler) CreateLocalUser(ctx context.Context, req *identityv1.CreateLocalUserRequest) (*identityv1.CreateLocalUserResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	if err := h.requireLocalAccounts(ctx); err != nil {
		return nil, err
	}
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}
	if usernameLooksLikeEmail(req.GetUsername()) {
		return nil, errUsernameIsEmail
	}
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	if req.GetPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}
	if _, err := mail.ParseAddress(req.GetEmail()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid email address")
	}
	if _, err := h.store.GetUserByUsername(ctx, req.GetUsername()); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "username %q already exists", req.GetUsername())
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, statusFromStoreErr(err)
	}
	if _, err := h.store.GetLocalUserByEmail(ctx, req.GetEmail()); err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "email %q already in use", req.GetEmail())
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, statusFromStoreErr(err)
	}

	identityID, err := h.accounts.CreateIdentity(ctx, kratos.Account{Username: req.GetUsername(), Email: req.GetEmail(), Name: req.GetName()}, req.GetPassword())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create sign-in identity: %v", err)
	}
	u, err := h.store.PreCreateLocalUser(ctx, req.GetUsername(), req.GetEmail(), req.GetName())
	if err != nil {
		_ = h.accounts.DeleteIdentity(ctx, identityID)
		return nil, statusFromStoreErr(err)
	}
	emitAccountCreated(ctx, h.acctCreatedPub, u.ID.String())
	return &identityv1.CreateLocalUserResponse{User: userToProto(u)}, nil
}

// ResetUserPassword sets a local account's password in Kratos. Refused
// during act-as.
func (h *AdminHandler) ResetUserPassword(ctx context.Context, req *identityv1.ResetUserPasswordRequest) (*identityv1.ResetUserPasswordResponse, error) {
	if _, err := h.auth.Authorize(ctx); err != nil {
		return nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return nil, err
	}
	if err := h.requireLocalAccounts(ctx); err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetUserId(), "user_id")
	if err != nil {
		return nil, err
	}
	if req.GetNewPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password required")
	}
	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	identityID, found, err := kratosIdentityID(ctx, h.accounts, u)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "find sign-in identity: %v", err)
	}
	if !found {
		return nil, status.Error(codes.FailedPrecondition, "the account has no local password to reset")
	}
	if err := h.accounts.SetPassword(ctx, identityID, req.GetNewPassword()); err != nil {
		return nil, status.Errorf(codes.Internal, "set password: %v", err)
	}
	return &identityv1.ResetUserPasswordResponse{}, nil
}

// UpdateUserProfile changes another user's name and email. The platform row
// is written first; a local account's Kratos traits follow, and a Kratos
// failure after the write is returned so the caller retries.
func (h *AdminHandler) UpdateUserProfile(ctx context.Context, req *identityv1.UpdateUserProfileRequest) (*identityv1.UpdateUserProfileResponse, error) {
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
	updated, err := h.store.UpdateUserProfile(ctx, id, req.GetEmail(), req.GetName(), u.FirstName, u.LastName, u.Timezone, u.Locale)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if u.LocalAccount && h.accounts != nil {
		identityID, found, err := kratosIdentityID(ctx, h.accounts, u)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "find sign-in identity: %v", err)
		}
		if found {
			if err := h.accounts.UpdateProfile(ctx, identityID, req.GetEmail(), req.GetName()); err != nil {
				return nil, status.Errorf(codes.Internal, "update sign-in identity: %v", err)
			}
		}
	}
	return &identityv1.UpdateUserProfileResponse{User: userToProto(updated)}, nil
}
