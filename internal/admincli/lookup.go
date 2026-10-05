// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"context"
	"fmt"
	"strings"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/google/uuid"
)

// resolveUserID accepts a UUID or an email and returns the user's id. An
// email must match exactly one user; no match or several is an error rather
// than a guess.
func resolveUserID(ctx context.Context, conn identityv1.IdentityReadServiceClient, emailOrID string) (string, error) {
	if isUUID(emailOrID) {
		return emailOrID, nil
	}
	if !strings.Contains(emailOrID, "@") {
		return "", fmt.Errorf("argument %q is neither a UUID nor an email", emailOrID)
	}
	if conn == nil {
		return "", fmt.Errorf("internal: nil read client for email lookup of %q", emailOrID)
	}
	resp, err := conn.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
		EmailSubstring: emailOrID,
		Limit:          2,
	})
	if err != nil {
		return "", fmt.Errorf("lookup email %s: %w", emailOrID, err)
	}
	// The lookup is by substring, so keep only exact matches.
	var matches []*identityv1.User
	for _, u := range resp.GetUsers() {
		if strings.EqualFold(u.GetEmail(), emailOrID) {
			matches = append(matches, u)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no user with email %s", emailOrID)
	case 1:
		return matches[0].GetId(), nil
	default:
		return "", fmt.Errorf("ambiguous: %d users share email %s", len(matches), emailOrID)
	}
}

// resolveGroupID accepts a UUID only: there is no lookup by group name, and
// a clear error beats resolving the wrong group.
func resolveGroupID(_ context.Context, _ identityv1.IdentityReadServiceClient, idOrName string) (string, error) {
	if isUUID(idOrName) {
		return idOrName, nil
	}
	return "", fmt.Errorf("group name lookup (%s) is not supported; pass a UUID instead", idOrName)
}

// isUUID reports whether s parses as a UUID.
func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}
