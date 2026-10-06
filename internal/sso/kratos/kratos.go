// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package kratos is identity's client for the Ory Kratos admin API, on Ory's
// Go SDK. Kratos holds local accounts, their passwords and every sign-in
// session; identity creates and updates local accounts, revokes a deleted
// account's credential, and lists and revokes sessions through it.
package kratos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ory "github.com/ory/kratos-client-go"
)

// DefaultTimeout bounds one admin call. A hung Kratos must surface as a
// refusal, not as a hung admin request.
const DefaultTimeout = 10 * time.Second

// DefaultSchemaID is the identity schema new local accounts get.
const DefaultSchemaID = "default"

// ErrNoEmail refuses a lookup by an empty email, which would match nothing
// and read as "no credential".
var ErrNoEmail = errors.New("kratos: empty email, cannot resolve an identity")

// Client calls the Kratos admin API. Safe for concurrent use.
type Client struct {
	api      ory.IdentityAPI
	schemaID string
}

// Option configures a Client.
type Option func(*Client)

// WithSchemaID sets the identity schema new accounts are created with.
func WithSchemaID(id string) Option { return func(c *Client) { c.schemaID = id } }

// New builds a Client for the Kratos admin base URL. A zero timeout falls
// back to DefaultTimeout.
func New(adminURL string, timeout time.Duration, opts ...Option) *Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cfg := ory.NewConfiguration()
	cfg.Servers = ory.ServerConfigurations{{URL: strings.TrimRight(adminURL, "/")}}
	cfg.HTTPClient = &http.Client{Timeout: timeout}
	c := &Client{api: ory.NewAPIClient(cfg).IdentityAPI, schemaID: DefaultSchemaID}
	for _, o := range opts {
		o(c)
	}
	return c
}

// RevokeResult reports what RevokeIdentity did. Found false means the
// account has no Kratos identity, which is normal for an SSO-only account.
type RevokeResult struct {
	IdentityID      string
	Found           bool
	Deactivated     bool
	SessionsRevoked bool
	PasswordRemoved bool
}

// RevokeIdentity makes the account behind email unable to sign in: it
// deactivates the identity first (so Kratos refuses it even if a later step
// fails), revokes its sessions, then deletes its password credential. A
// missing password credential is not an error.
func (c *Client) RevokeIdentity(ctx context.Context, email string) (RevokeResult, error) {
	ref, err := c.FindIdentity(ctx, email)
	if err != nil {
		return RevokeResult{}, err
	}
	if !ref.Found {
		return RevokeResult{}, nil
	}
	res := RevokeResult{IdentityID: ref.ID, Found: true}

	patch := []ory.JsonPatch{{Op: "replace", Path: "/state", Value: "inactive"}}
	if _, resp, err := c.api.PatchIdentity(ctx, ref.ID).JsonPatch(patch).Execute(); err != nil {
		return res, fmt.Errorf("deactivate identity: %w", callErr(resp, err))
	}
	res.Deactivated = true

	if resp, err := c.api.DeleteIdentitySessions(ctx, ref.ID).Execute(); err != nil {
		return res, fmt.Errorf("revoke identity sessions: %w", callErr(resp, err))
	}
	res.SessionsRevoked = true

	resp, err := c.api.DeleteIdentityCredentials(ctx, ref.ID, "password").Execute()
	switch {
	case isStatus(resp, http.StatusNotFound):
	case err != nil:
		return res, fmt.Errorf("delete password credential: %w", callErr(resp, err))
	default:
		res.PasswordRemoved = true
	}
	return res, nil
}

// IdentityRef is what a read-only lookup found. Found false means the lookup
// worked and matched nothing.
type IdentityRef struct {
	ID    string
	Found bool
	// The Kratos state, "active" or "inactive"; empty when not found.
	State string
}

// FindIdentity resolves email to an identity without changing anything. It
// never asks for credential material.
func (c *Client) FindIdentity(ctx context.Context, email string) (IdentityRef, error) {
	if strings.TrimSpace(email) == "" {
		return IdentityRef{}, ErrNoEmail
	}
	ids, resp, err := c.api.ListIdentities(ctx).CredentialsIdentifier(email).Execute()
	if err != nil {
		return IdentityRef{}, fmt.Errorf("lookup identity: %w", callErr(resp, err))
	}
	if len(ids) == 0 || ids[0].Id == "" {
		return IdentityRef{}, nil
	}
	return IdentityRef{ID: ids[0].Id, Found: true, State: ids[0].GetState()}, nil
}

// Account is a local account's traits.
type Account struct {
	Username string
	Email    string
	Name     string
}

func (a Account) traits() map[string]any {
	return map[string]any{"email": a.Email, "username": a.Username, "name": a.Name}
}

// CreateIdentity creates an active local identity with a password and
// returns its id.
func (c *Client) CreateIdentity(ctx context.Context, a Account, password string) (string, error) {
	body := ory.CreateIdentityBody{
		SchemaId:    c.schemaID,
		Traits:      a.traits(),
		State:       ory.PtrString("active"),
		Credentials: passwordCredentials(password),
	}
	id, resp, err := c.api.CreateIdentity(ctx).CreateIdentityBody(body).Execute()
	if err != nil {
		return "", fmt.Errorf("create identity: %w", callErr(resp, err))
	}
	return id.Id, nil
}

// DeleteIdentity removes an identity, for rolling back a local account whose
// row couldn't be written.
func (c *Client) DeleteIdentity(ctx context.Context, identityID string) error {
	if resp, err := c.api.DeleteIdentity(ctx, identityID).Execute(); err != nil && !isStatus(resp, http.StatusNotFound) {
		return fmt.Errorf("delete identity: %w", callErr(resp, err))
	}
	return nil
}

// SetPassword replaces an identity's password, keeping its traits and state.
func (c *Client) SetPassword(ctx context.Context, identityID, password string) error {
	return c.update(ctx, identityID, func(b *ory.UpdateIdentityBody) {
		b.Credentials = passwordCredentials(password)
	})
}

// UpdateProfile replaces an identity's email and name traits.
func (c *Client) UpdateProfile(ctx context.Context, identityID, email, name string) error {
	return c.update(ctx, identityID, func(b *ory.UpdateIdentityBody) {
		b.Traits["email"] = email
		b.Traits["name"] = name
	})
}

func (c *Client) update(ctx context.Context, identityID string, change func(*ory.UpdateIdentityBody)) error {
	cur, resp, err := c.api.GetIdentity(ctx, identityID).Execute()
	if err != nil {
		return fmt.Errorf("get identity: %w", callErr(resp, err))
	}
	traits, _ := cur.Traits.(map[string]any)
	if traits == nil {
		traits = map[string]any{}
	}
	body := ory.UpdateIdentityBody{SchemaId: cur.SchemaId, State: cur.GetState(), Traits: traits}
	change(&body)
	if _, resp, err := c.api.UpdateIdentity(ctx, identityID).UpdateIdentityBody(body).Execute(); err != nil {
		return fmt.Errorf("update identity: %w", callErr(resp, err))
	}
	return nil
}

func passwordCredentials(password string) *ory.IdentityWithCredentials {
	return &ory.IdentityWithCredentials{Password: &ory.IdentityWithCredentialsPassword{
		Config: &ory.IdentityWithCredentialsPasswordConfig{Password: ory.PtrString(password)},
	}}
}

// Session is one Kratos session.
type Session struct {
	ID              string
	IdentityID      string
	IssuedAt        time.Time
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Active          bool
	UserAgent       string
	ClientIP        string
}

// ListSessions lists an identity's sessions, active and ended.
func (c *Client) ListSessions(ctx context.Context, identityID string) ([]Session, error) {
	ss, resp, err := c.api.ListIdentitySessions(ctx, identityID).Execute()
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", callErr(resp, err))
	}
	out := make([]Session, 0, len(ss))
	for _, s := range ss {
		out = append(out, toSession(identityID, s))
	}
	return out, nil
}

// RevokeIdentitySessions revokes every session of an identity and returns how
// many were active.
func (c *Client) RevokeIdentitySessions(ctx context.Context, identityID string) (int, error) {
	active, resp, err := c.api.ListIdentitySessions(ctx, identityID).Active(true).Execute()
	if err != nil {
		return 0, fmt.Errorf("list sessions: %w", callErr(resp, err))
	}
	if resp, err := c.api.DeleteIdentitySessions(ctx, identityID).Execute(); err != nil && !isStatus(resp, http.StatusNotFound) {
		return 0, fmt.Errorf("revoke sessions: %w", callErr(resp, err))
	}
	return len(active), nil
}

// RevokeSession revokes one session. It reports false for a session Kratos
// doesn't know.
func (c *Client) RevokeSession(ctx context.Context, sessionID string) (bool, error) {
	resp, err := c.api.DisableSession(ctx, sessionID).Execute()
	if isStatus(resp, http.StatusNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", callErr(resp, err))
	}
	return true, nil
}

func toSession(identityID string, s ory.Session) Session {
	out := Session{ID: s.Id, IdentityID: identityID, Active: s.GetActive()}
	if s.IssuedAt != nil {
		out.IssuedAt = *s.IssuedAt
	}
	if s.AuthenticatedAt != nil {
		out.AuthenticatedAt = *s.AuthenticatedAt
	}
	if s.ExpiresAt != nil {
		out.ExpiresAt = *s.ExpiresAt
	}
	if s.Identity != nil && s.Identity.Id != "" {
		out.IdentityID = s.Identity.Id
	}
	if n := len(s.Devices); n > 0 {
		out.UserAgent = s.Devices[n-1].GetUserAgent()
		out.ClientIP = s.Devices[n-1].GetIpAddress()
	}
	return out
}

func isStatus(resp *http.Response, code int) bool { return resp != nil && resp.StatusCode == code }

// callErr keeps the status and drops the response body, which can echo
// request data.
func callErr(resp *http.Response, err error) error {
	if resp != nil {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return err
}
