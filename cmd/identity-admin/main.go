// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Command identity-admin is the operators' CLI for the identity service. It
// calls the admin services over mTLS and labels every call with the operator
// named in AUDIT_USER.
package main

import (
	"fmt"
	"os"

	"github.com/Steward-GRC/steward-identity/internal/admincli"
)

func main() {
	if err := admincli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "identity-admin:", err)
		os.Exit(1)
	}
}
