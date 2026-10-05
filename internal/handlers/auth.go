// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"slices"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// AuditOperatorMetadataKey carries the admin CLI operator's label.
const AuditOperatorMetadataKey = "x-audit-operator"

// RoleSource reports a user's global roles by platform user id. Roles never
// travel on the wire, so identity reads its own: StoreRoles in production.
type RoleSource interface {
	UserRoles(ctx context.Context, subject string) ([]string, error)
}

// StoreRoles reads roles from the store.
type StoreRoles struct{ Store *store.Store }

// UserRoles returns the global roles of an enabled, live user; anyone else
// has none.
func (r StoreRoles) UserRoles(ctx context.Context, subject string) ([]string, error) {
	id, err := uuid.Parse(subject)
	if err != nil {
		return nil, nil
	}
	u, err := r.Store.GetUser(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if !u.Enabled || u.DeletedAt != nil {
		return nil, nil
	}
	return u.Roles, nil
}

// AdminAuth gates the admin services. A call is admitted from the admin
// CLI (a verified client certificate whose SPIFFE ID is AdminCLIID) or from
// a forwarded actor whose subject holds site-admin.
type AdminAuth struct {
	AdminCLIID string
	Roles      RoleSource
}

// adminActor is who an admitted call acts for. ActorUserID is set for a
// forwarded actor (with Impersonator during act-as); ActorExternal names the
// admin CLI operator. They are mutually exclusive.
type adminActor struct {
	ActorUserID   string
	Impersonator  string
	ActorExternal string
}

// Authorize admits the call or returns ADMIN_AUTHZ_REQUIRED.
func (a *AdminAuth) Authorize(ctx context.Context) (adminActor, error) {
	if a.AdminCLIID != "" && peerSPIFFEID(ctx) == a.AdminCLIID {
		return adminActor{ActorExternal: firstMD(ctx, AuditOperatorMetadataKey)}, nil
	}
	act, ok := grpcactor.FromContext(ctx)
	if !ok || a.Roles == nil {
		return adminActor{}, errcodes.Error(ctx, errcodes.AdminAuthzRequired())
	}
	if a.hasRole(ctx, act.Subject, "site-admin") {
		return adminActor{ActorUserID: act.Subject, Impersonator: act.Impersonator}, nil
	}
	return adminActor{}, errcodes.Error(ctx, errcodes.AdminAuthzRequired())
}

func (a *AdminAuth) hasRole(ctx context.Context, subject, role string) bool {
	roles, err := a.Roles.UserRoles(ctx, subject)
	return err == nil && slices.Contains(roles, role)
}

// callerSubject returns the forwarded actor's subject: the user a
// self-service call acts on.
func callerSubject(ctx context.Context) (string, bool) {
	act, ok := grpcactor.FromContext(ctx)
	if !ok || act.Subject == "" {
		return "", false
	}
	return act.Subject, true
}

// actingAs reports whether an admin is acting as another user on this call.
func actingAs(ctx context.Context) bool {
	act, ok := grpcactor.FromContext(ctx)
	return ok && act.Impersonated()
}

// refuseWhileActingAs blocks the actions that must never run during act-as:
// passwords and second factors, deletions, and role and permission changes.
func refuseWhileActingAs(ctx context.Context) error {
	if actingAs(ctx) {
		return errcodes.Error(ctx, errcodes.ActAsForbidden())
	}
	return nil
}

// peerSPIFFEID returns the URI SAN of a verified client certificate, or "".
func peerSPIFFEID(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return ""
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.VerifiedChains) == 0 || len(info.State.VerifiedChains[0]) == 0 {
		return ""
	}
	leaf := info.State.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 || leaf.URIs[0].Scheme != "spiffe" {
		return ""
	}
	return leaf.URIs[0].String()
}

func firstMD(ctx context.Context, key string) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(key); len(v) > 0 {
			return v[0]
		}
	}
	return ""
}
