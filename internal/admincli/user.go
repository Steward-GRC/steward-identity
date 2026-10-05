// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"github.com/spf13/cobra"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// newUserCommand returns the `identity-admin user ...` subtree.
func newUserCommand(opt rootCommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "User management subcommands",
	}
	cmd.AddCommand(newUserListCmd(opt))
	cmd.AddCommand(newUserShowCmd(opt))
	cmd.AddCommand(newUserEnableCmd(opt))
	cmd.AddCommand(newUserDisableCmd(opt))
	cmd.AddCommand(newUserGrantRoleCmd(opt))
	cmd.AddCommand(newUserRevokeRoleCmd(opt))
	return cmd
}

func newUserListCmd(opt rootCommandOptions) *cobra.Command {
	var enabled, disabled bool
	var emailContains string
	var limit int32
	c := &cobra.Command{
		Use:   "list",
		Short: "List users (optionally filtered by enabled/disabled state and/or email substring)",
		Long: "List users by paging through IdentityReadService.ListUsersByEmail. " +
			"--email-contains is matched case-insensitively as a substring; " +
			"--enabled / --disabled filter the page client-side (the read RPC " +
			"surfaces every match and the CLI prints only those that " +
			"satisfy the predicate).",
		RunE: func(cmd *cobra.Command, args []string) error {
			if enabled && disabled {
				return errMutuallyExclusiveFlag("--enabled", "--disabled")
			}
			ctx, cancel := commandContext()
			defer cancel()
			conn, cleanup, err := opt.dialRead(ctx, opt)
			if err != nil {
				return err
			}
			defer cleanup()
			var pageToken string
			for {
				resp, err := conn.ListUsersByEmail(ctx, &identityv1.ListUsersByEmailRequest{
					EmailSubstring: emailContains,
					Limit:          limit,
					PageToken:      pageToken,
				})
				if err != nil {
					return err
				}
				for _, u := range resp.GetUsers() {
					if enabled && !u.GetEnabled() {
						continue
					}
					if disabled && u.GetEnabled() {
						continue
					}
					_ = printUser(cmd, u)
				}
				if resp.GetNextPageToken() == "" {
					return nil
				}
				pageToken = resp.GetNextPageToken()
			}
		},
	}
	c.Flags().BoolVar(&enabled, "enabled", false, "Show only enabled users")
	c.Flags().BoolVar(&disabled, "disabled", false, "Show only disabled users")
	c.Flags().StringVar(&emailContains, "email-contains", "", "Case-insensitive email substring filter")
	c.Flags().Int32Var(&limit, "limit", 50, "Per-page limit (server caps at 200)")
	return c
}

func newUserShowCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show <email-or-id>",
		Short: "Show a single user by email or platform UUID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := commandContext()
			defer cancel()
			conn, cleanup, err := opt.dialRead(ctx, opt)
			if err != nil {
				return err
			}
			defer cleanup()
			userID, err := resolveUserID(ctx, conn, args[0])
			if err != nil {
				return err
			}
			resp, err := conn.GetUser(ctx, &identityv1.GetUserRequest{UserId: userID})
			if err != nil {
				return err
			}
			return printUser(cmd, resp.GetUser())
		},
	}
}

func newUserEnableCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "enable <email-or-id>",
		Short: "Enable a user (soft-enable)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnableDisable(cmd, opt, args[0], true)
		},
	}
}

func newUserDisableCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "disable <email-or-id>",
		Short: "Disable a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnableDisable(cmd, opt, args[0], false)
		},
	}
}

func newUserGrantRoleCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "grant-role <email-or-id> <role>",
		Short: "Grant a global role (admin | site-admin | template-admin | compliance-admin)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoleMutation(cmd, opt, args[0], args[1], true)
		},
	}
}

func newUserRevokeRoleCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke-role <email-or-id> <role>",
		Short: "Revoke a role",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRoleMutation(cmd, opt, args[0], args[1], false)
		},
	}
}

// runEnableDisable issues EnableUser/DisableUser on the admin client.
func runEnableDisable(cmd *cobra.Command, opt rootCommandOptions, emailOrID string, enable bool) error {
	ctx, cancel := commandContext()
	defer cancel()
	ctx, err := withAuditContext(ctx, opt)
	if err != nil {
		return err
	}
	read, readCleanup, err := opt.dialRead(ctx, opt)
	if err != nil {
		return err
	}
	defer readCleanup()
	userID, err := resolveUserID(ctx, read, emailOrID)
	if err != nil {
		return err
	}
	admin, cleanup, err := opt.dialAdmin(ctx, opt)
	if err != nil {
		return err
	}
	defer cleanup()
	if enable {
		resp, err := admin.EnableUser(ctx, &identityv1.EnableUserRequest{UserId: userID})
		if err != nil {
			return err
		}
		return printUser(cmd, resp.GetUser())
	}
	resp, err := admin.DisableUser(ctx, &identityv1.DisableUserRequest{UserId: userID})
	if err != nil {
		return err
	}
	return printUser(cmd, resp.GetUser())
}

func runRoleMutation(cmd *cobra.Command, opt rootCommandOptions, emailOrID, role string, grant bool) error {
	ctx, cancel := commandContext()
	defer cancel()
	ctx, err := withAuditContext(ctx, opt)
	if err != nil {
		return err
	}
	read, readCleanup, err := opt.dialRead(ctx, opt)
	if err != nil {
		return err
	}
	defer readCleanup()
	userID, err := resolveUserID(ctx, read, emailOrID)
	if err != nil {
		return err
	}
	admin, cleanup, err := opt.dialAdmin(ctx, opt)
	if err != nil {
		return err
	}
	defer cleanup()
	if grant {
		resp, err := admin.GrantRole(ctx, &identityv1.GrantRoleRequest{UserId: userID, Role: role})
		if err != nil {
			return err
		}
		return printUser(cmd, resp.GetUser())
	}
	resp, err := admin.RevokeRole(ctx, &identityv1.RevokeRoleRequest{UserId: userID, Role: role})
	if err != nil {
		return err
	}
	return printUser(cmd, resp.GetUser())
}

// printUser emits a stable key=value form so operator scripts can grep.
func printUser(cmd *cobra.Command, u *identityv1.User) error {
	if u == nil {
		printlnf(cmd, "user=<nil>")
		return nil
	}
	printlnf(cmd, "id=%s email=%s name=%s enabled=%t roles=%v groups=%v",
		u.GetId(), u.GetEmail(), u.GetName(), u.GetEnabled(),
		u.GetRoles(), u.GetGroups())
	return nil
}
