// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"time"

	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

var errNoSignIn = errors.New("identity: the Kratos admin API isn't configured")

// signInService is the Kratos admin surface identity uses: local accounts,
// passwords, credential revoke and sessions. *kratos.Client implements it.
type signInService interface {
	FindIdentity(ctx context.Context, email string) (kratos.IdentityRef, error)
	RevokeIdentity(ctx context.Context, email string) (kratos.RevokeResult, error)
	CreateIdentity(ctx context.Context, a kratos.Account, password string) (string, error)
	SetPassword(ctx context.Context, identityID, password string) error
	UpdateProfile(ctx context.Context, identityID, email, name string) error
	ListSessions(ctx context.Context, identityID string) ([]kratos.Session, error)
	RevokeIdentitySessions(ctx context.Context, identityID string) (int, error)
	RevokeSession(ctx context.Context, sessionID string) (bool, error)
}

// kratosIdentityID finds the Kratos identity behind u: its external subject
// once a sign-in has linked one, else a lookup by email. found is false for
// an account with no Kratos identity.
func kratosIdentityID(ctx context.Context, k signInService, u store.User) (id string, found bool, err error) {
	if u.ExternalSubject != "" {
		return u.ExternalSubject, true, nil
	}
	if u.Email == "" {
		return "", false, nil
	}
	ref, err := k.FindIdentity(ctx, u.Email)
	if err != nil {
		return "", false, err
	}
	return ref.ID, ref.Found, nil
}

// revokeAllSessions revokes every Kratos session of u and returns how many
// were active. It fails closed: a revoke that can't run is an error, never a
// silent zero.
func revokeAllSessions(ctx context.Context, k signInService, u store.User) (int, error) {
	if k == nil {
		return 0, errcodes.Error(ctx, errcodes.SessionRevokeUnavailable(errNoSignIn))
	}
	id, found, err := kratosIdentityID(ctx, k, u)
	if err != nil {
		return 0, errcodes.Error(ctx, errcodes.SessionRevokeUnavailable(err))
	}
	if !found {
		return 0, nil
	}
	n, err := k.RevokeIdentitySessions(ctx, id)
	if err != nil {
		return 0, errcodes.Error(ctx, errcodes.SessionRevokeUnavailable(err))
	}
	return n, nil
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
