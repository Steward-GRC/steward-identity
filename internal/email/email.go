// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package email sends identity's one-time codes as plain text through a
// go-email sender.
package email

import (
	"context"

	goemail "github.com/Bugs5382/go-email"
)

// Mailer sends single-recipient plain-text messages from one address.
type Mailer struct {
	s    goemail.Sender
	from string
}

// New returns a Mailer sending through s from the from address.
func New(s goemail.Sender, from string) *Mailer { return &Mailer{s: s, from: from} }

// Send delivers body to one recipient.
func (m *Mailer) Send(ctx context.Context, to, subject, body string) error {
	return m.s.Send(ctx, goemail.Message{From: m.from, To: []string{to}, Subject: subject, Text: body})
}
