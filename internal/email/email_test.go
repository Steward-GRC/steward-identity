// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package email_test

import (
	"context"
	"errors"
	"testing"

	goemail "github.com/Bugs5382/go-email"
	"github.com/stretchr/testify/require"

	"github.com/Steward-GRC/steward-identity/internal/email"
)

type captureTransport struct {
	got []goemail.Message
	err error
}

func (c *captureTransport) Send(_ context.Context, m goemail.Message) error {
	c.got = append(c.got, m)
	return c.err
}

func TestSendBuildsAPlainTextMessageFromTheSender(t *testing.T) {
	tr := &captureTransport{}
	m := email.New(goemail.New(tr, goemail.WithMiddleware(goemail.Validate())), "no-reply@example.org")

	require.NoError(t, m.Send(context.Background(), "alice@example.org", "Your sign-in code", "123456"))
	require.Len(t, tr.got, 1)
	require.Equal(t, "no-reply@example.org", tr.got[0].From)
	require.Equal(t, []string{"alice@example.org"}, tr.got[0].To)
	require.Equal(t, "Your sign-in code", tr.got[0].Subject)
	require.Equal(t, "123456", tr.got[0].Text)
	require.Empty(t, tr.got[0].HTML)
}

func TestSendReturnsTheTransportError(t *testing.T) {
	tr := &captureTransport{err: errors.New("relay refused")}
	m := email.New(goemail.New(tr), "no-reply@example.org")
	require.Error(t, m.Send(context.Background(), "alice@example.org", "s", "b"))
}
