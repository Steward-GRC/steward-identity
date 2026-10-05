// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"github.com/spf13/cobra"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// newBootstrapCommand returns `identity-admin bootstrap initial-admin ...`.
// The server returns the existing admin with created=false once one exists.
func newBootstrapCommand(opt rootCommandOptions) *cobra.Command {
	cmd := &cobra.Command{Use: "bootstrap", Short: "Bootstrap subcommands"}
	cmd.AddCommand(newBootstrapInitialAdminCmd(opt))
	return cmd
}

func newBootstrapInitialAdminCmd(opt rootCommandOptions) *cobra.Command {
	var subject, email string
	c := &cobra.Command{
		Use:   "initial-admin",
		Short: "Create the first admin user (does nothing once an admin exists)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if subject == "" || email == "" {
				return errMissingRequiredFlags("--subject", "--email")
			}
			ctx, cancel := commandContext()
			defer cancel()
			ctx, err := withAuditContext(ctx, opt)
			if err != nil {
				return err
			}
			admin, cleanup, err := opt.dialAdmin(ctx, opt)
			if err != nil {
				return err
			}
			defer cleanup()
			resp, err := admin.BootstrapInitialAdmin(ctx, &identityv1.BootstrapInitialAdminRequest{
				ExternalSubject: subject,
				Email:           email,
			})
			if err != nil {
				return err
			}
			printlnf(cmd, "created=%t id=%s email=%s roles=%v",
				resp.GetCreated(), resp.GetUser().GetId(),
				resp.GetUser().GetEmail(), resp.GetUser().GetRoles())
			return nil
		},
	}
	c.Flags().StringVar(&subject, "subject", "", "Sign-in subject of the user to promote")
	c.Flags().StringVar(&email, "email", "", "Email of the user (used if JIT provision is needed)")
	return c
}

func errMissingRequiredFlags(flags ...string) error {
	return errSurfaceMissingFlags(flags...)
}
