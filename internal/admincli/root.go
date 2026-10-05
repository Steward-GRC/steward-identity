// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package admincli is the identity-admin command tree: users, groups and the
// first-admin bootstrap. Each leaf turns its arguments into one identity
// request and prints the answer as key=value pairs operator scripts can grep.
// Every admin call carries the operator's label.
package admincli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/metadata"
)

// CommandTimeout caps one CLI invocation.
const CommandTimeout = 30 * time.Second

// OperatorMetadataKey carries the operator label; the identity admin
// services record it as the audit actor of a CLI call.
const OperatorMetadataKey = "x-audit-operator"

var errAuditUserMissing = errors.New("AUDIT_USER not set: every admin call must name the operator")

// rootCommandOptions holds the test seams; the zero value is production.
type rootCommandOptions struct {
	dialAdmin AdminDialer
	dialRead  ReadDialer
	envLookup func(string) string
}

// NewRootCommand returns the identity-admin command tree.
func NewRootCommand() *cobra.Command {
	return newRootCommandWithOptions(rootCommandOptions{})
}

func newRootCommandWithOptions(opt rootCommandOptions) *cobra.Command {
	if opt.dialAdmin == nil {
		opt.dialAdmin = productionDialAdmin
	}
	if opt.dialRead == nil {
		opt.dialRead = productionDialRead
	}
	if opt.envLookup == nil {
		opt.envLookup = os.Getenv
	}
	root := &cobra.Command{
		Use:          "identity-admin",
		Short:        "Admin CLI for the Steward identity service",
		Long:         "identity-admin manages Steward users, roles, groups and the first admin.",
		SilenceUsage: true,
	}
	root.AddCommand(newUserCommand(opt))
	root.AddCommand(newGroupCommand(opt))
	root.AddCommand(newBootstrapCommand(opt))
	return root
}

// withAuditContext attaches AUDIT_USER as the operator label.
func withAuditContext(ctx context.Context, opt rootCommandOptions) (context.Context, error) {
	op := opt.envLookup("AUDIT_USER")
	if op == "" {
		return nil, errAuditUserMissing
	}
	return metadata.AppendToOutgoingContext(ctx, OperatorMetadataKey, op), nil
}

func commandContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), CommandTimeout)
}

// printlnf writes to the command's stdout, so tests can capture it.
func printlnf(cmd *cobra.Command, format string, args ...any) {
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), format+"\n", args...)
}
