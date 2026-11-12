// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrWrongPassword is the current password failing Kratos's own sign-in check.
var ErrWrongPassword = errors.New("kratos: the current password is wrong")

// ErrWeakPassword is Kratos's password policy refusing the new password.
var ErrWeakPassword = errors.New("kratos: the new password does not meet the password policy")

// Kratos message ids this package acts on.
const (
	msgCredentialsInvalid = 4000006
	// The password policy: a generic violation, too similar to the
	// identifier, too short, too long, found in a data breach.
	msgPolicyViolation = 4000005
	msgPolicySimilar   = 4000031
	msgPolicyMinLength = 4000032
	msgPolicyMaxLength = 4000033
	msgPolicyBreached  = 4000034
)

// maxBody bounds what is read back from Kratos.
const maxBody = 1 << 20

// Public calls the Kratos public API. The admin API sets a password without
// applying the password policy, and it cannot check a current one, so a
// person's own password change goes through Kratos's self-service flows
// instead: the sign-in flow proves the current password, and the settings flow
// applies the new one under Kratos's policy. Safe for concurrent use.
type Public struct {
	base string
	http *http.Client
}

// NewPublic builds a Public for the Kratos public base URL. A zero timeout
// falls back to DefaultTimeout.
func NewPublic(publicURL string, timeout time.Duration) *Public {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Public{base: strings.TrimRight(publicURL, "/"), http: &http.Client{Timeout: timeout}}
}

// ChangePassword proves current for the account behind identifier (its
// sign-in identifier, the email), then sets next. It returns ErrWrongPassword
// when current is not the password, and ErrWeakPassword when Kratos's policy
// refuses next. Any other failure is a plain error that carries no password,
// token or response body.
//
// The proof is a real sign-in, so it makes a session. That session is the
// one the settings flow needs, and it is ended before this returns, on every
// path.
func (p *Public) ChangePassword(ctx context.Context, identifier, current, next string) error {
	if identifier == "" || current == "" || next == "" {
		return errors.New("kratos: identifier, current and new password are required")
	}
	token, err := p.signIn(ctx, identifier, current)
	if err != nil {
		return err
	}
	defer p.signOut(ctx, token)
	return p.applyPassword(ctx, token, next)
}

// signIn runs the native sign-in flow and returns the session token.
func (p *Public) signIn(ctx context.Context, identifier, password string) (string, error) {
	flow, err := p.newFlow(ctx, "/self-service/login/api", "")
	if err != nil {
		return "", fmt.Errorf("start sign-in flow: %w", err)
	}
	status, body, err := p.do(ctx, http.MethodPost, "/self-service/login?flow="+url.QueryEscape(flow), "",
		map[string]string{"method": "password", "identifier": identifier, "password": password})
	if err != nil {
		return "", fmt.Errorf("sign-in flow: %w", err)
	}
	switch {
	case status == http.StatusOK:
		var out struct {
			SessionToken string `json:"session_token"`
		}
		if err := json.Unmarshal(body, &out); err != nil || out.SessionToken == "" {
			return "", errors.New("sign-in flow: no session token in the answer")
		}
		return out.SessionToken, nil
	case status == http.StatusBadRequest && hasMessage(body, msgCredentialsInvalid):
		return "", ErrWrongPassword
	default:
		return "", fmt.Errorf("sign-in flow: unexpected status %d", status)
	}
}

// applyPassword runs the native settings flow on the session and sets the
// password.
func (p *Public) applyPassword(ctx context.Context, token, password string) error {
	flow, err := p.newFlow(ctx, "/self-service/settings/api", token)
	if err != nil {
		return fmt.Errorf("start settings flow: %w", err)
	}
	status, body, err := p.do(ctx, http.MethodPost, "/self-service/settings?flow="+url.QueryEscape(flow), token,
		map[string]string{"method": "password", "password": password})
	if err != nil {
		return fmt.Errorf("settings flow: %w", err)
	}
	switch {
	case status == http.StatusOK:
		return nil
	case status == http.StatusBadRequest && hasMessage(body, msgPolicyViolation, msgPolicySimilar,
		msgPolicyMinLength, msgPolicyMaxLength, msgPolicyBreached):
		return ErrWeakPassword
	default:
		return fmt.Errorf("settings flow: unexpected status %d", status)
	}
}

// signOut ends the session behind token. It outlives a cancelled request so
// the throwaway session is not left behind, and a failure is not fatal: the
// password change already has its answer, and the session is short-lived.
func (p *Public) signOut(ctx context.Context, token string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), DefaultTimeout)
	defer cancel()
	_, _, _ = p.do(ctx, http.MethodDelete, "/self-service/logout/api", "", map[string]string{"session_token": token})
}

func (p *Public) newFlow(ctx context.Context, path, token string) (string, error) {
	status, body, err := p.do(ctx, http.MethodGet, path, token, nil)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &out) != nil || out.ID == "" {
		return "", fmt.Errorf("unexpected status %d", status)
	}
	return out.ID, nil
}

// do sends one request. The transport error is reduced to its kind so a URL
// or a body never reaches a log through it.
func (p *Public) do(ctx context.Context, method, path, token string, payload any) (int, []byte, error) {
	var rd io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, errors.New("encode request")
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, rd)
	if err != nil {
		return 0, nil, errors.New("build request")
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Session-Token", token)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, nil, errors.New("read answer")
	}
	return resp.StatusCode, b, nil
}

// hasMessage reports whether any message in a Kratos flow answer, at the flow
// or on any node, carries one of ids.
func hasMessage(body []byte, ids ...int) bool {
	type msg struct {
		ID int `json:"id"`
	}
	var f struct {
		UI struct {
			Messages []msg `json:"messages"`
			Nodes    []struct {
				Messages []msg `json:"messages"`
			} `json:"nodes"`
		} `json:"ui"`
	}
	if json.Unmarshal(body, &f) != nil {
		return false
	}
	match := func(ms []msg) bool {
		for _, m := range ms {
			for _, id := range ids {
				if m.ID == id {
					return true
				}
			}
		}
		return false
	}
	if match(f.UI.Messages) {
		return true
	}
	for _, n := range f.UI.Nodes {
		if match(n.Messages) {
			return true
		}
	}
	return false
}
