// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"github.com/spf13/cobra"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// newGroupCommand returns the `identity-admin group ...` subtree.
func newGroupCommand(opt rootCommandOptions) *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Group management subcommands"}
	cmd.AddCommand(newGroupListCmd(opt))
	cmd.AddCommand(newGroupShowCmd(opt))
	cmd.AddCommand(newGroupCreateCmd(opt))
	cmd.AddCommand(newGroupRenameCmd(opt))
	cmd.AddCommand(newGroupDeleteCmd(opt))
	cmd.AddCommand(newGroupAddMemberCmd(opt))
	cmd.AddCommand(newGroupRemoveMemberCmd(opt))
	cmd.AddCommand(newGroupSetParentCmd(opt))
	return cmd
}

func newGroupListCmd(opt rootCommandOptions) *cobra.Command {
	var parent string
	var descendants bool
	var limit int32
	c := &cobra.Command{
		Use:   "list",
		Short: "List groups (optionally under a parent, optionally including descendants)",
		Long: "List groups via IdentityReadService.ListGroups. With no --parent, " +
			"root-level groups are returned. --descendants expands to the " +
			"transitive closure rooted at --parent (or the whole tree when " +
			"--parent is omitted).",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := commandContext()
			defer cancel()
			conn, cleanup, err := opt.dialRead(ctx, opt)
			if err != nil {
				return err
			}
			defer cleanup()
			var pageToken string
			for {
				resp, err := conn.ListGroups(ctx, &identityv1.ListGroupsRequest{
					ParentId:           parent,
					IncludeDescendants: descendants,
					Limit:              limit,
					PageToken:          pageToken,
				})
				if err != nil {
					return err
				}
				for _, g := range resp.GetGroups() {
					_ = printGroup(cmd, g)
				}
				if resp.GetNextPageToken() == "" {
					return nil
				}
				pageToken = resp.GetNextPageToken()
			}
		},
	}
	c.Flags().StringVar(&parent, "parent", "", "Parent group UUID (omit for root-level)")
	c.Flags().BoolVar(&descendants, "descendants", false, "Include all descendants of --parent (or whole tree when --parent is empty)")
	c.Flags().Int32Var(&limit, "limit", 50, "Per-page limit (server caps at 200)")
	return c
}

func newGroupShowCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "show <id-or-name>",
		Short: "Show a single group by UUID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := commandContext()
			defer cancel()
			conn, cleanup, err := opt.dialRead(ctx, opt)
			if err != nil {
				return err
			}
			defer cleanup()
			id, err := resolveGroupID(ctx, conn, args[0])
			if err != nil {
				return err
			}
			resp, err := conn.GetGroup(ctx, &identityv1.GetGroupRequest{GroupId: id})
			if err != nil {
				return err
			}
			return printGroup(cmd, resp.GetGroup())
		},
	}
}

func newGroupCreateCmd(opt rootCommandOptions) *cobra.Command {
	var parent string
	c := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new group (optionally under a parent UUID)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			resp, err := admin.CreateGroup(ctx, &identityv1.CreateGroupRequest{
				Name:     args[0],
				ParentId: parent,
			})
			if err != nil {
				return err
			}
			return printGroup(cmd, resp.GetGroup())
		},
	}
	c.Flags().StringVar(&parent, "parent", "", "Parent group UUID (omit for root)")
	return c
}

func newGroupRenameCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "rename <id> <new-name>",
		Short: "Rename a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			resp, err := admin.RenameGroup(ctx, &identityv1.RenameGroupRequest{
				GroupId: args[0],
				NewName: args[1],
			})
			if err != nil {
				return err
			}
			return printGroup(cmd, resp.GetGroup())
		},
	}
}

func newGroupDeleteCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a group (refuses if it has members or descendants)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			resp, err := admin.DeleteGroup(ctx, &identityv1.DeleteGroupRequest{GroupId: args[0]})
			if err != nil {
				return err
			}
			printlnf(cmd, "deleted=%s", resp.GetGroupId())
			return nil
		},
	}
}

func newGroupAddMemberCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "add-member <group-id> <user-id-or-email>",
		Short: "Add a user to a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupMembership(cmd, opt, args[0], args[1], true)
		},
	}
}

func newGroupRemoveMemberCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "remove-member <group-id> <user-id-or-email>",
		Short: "Remove a user from a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGroupMembership(cmd, opt, args[0], args[1], false)
		},
	}
}

func newGroupSetParentCmd(opt rootCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "set-parent <id> <new-parent-id>",
		Short: "Re-parent a group (use \"\" to move to root)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			resp, err := admin.SetGroupParent(ctx, &identityv1.SetGroupParentRequest{
				GroupId:     args[0],
				NewParentId: args[1],
			})
			if err != nil {
				return err
			}
			return printGroup(cmd, resp.GetGroup())
		},
	}
}

func runGroupMembership(cmd *cobra.Command, opt rootCommandOptions, groupID, userArg string, add bool) error {
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
	userID, err := resolveUserID(ctx, read, userArg)
	if err != nil {
		return err
	}
	admin, cleanup, err := opt.dialAdmin(ctx, opt)
	if err != nil {
		return err
	}
	defer cleanup()
	if add {
		_, err := admin.AddUserToGroup(ctx, &identityv1.AddUserToGroupRequest{
			UserId: userID, GroupId: groupID,
		})
		if err != nil {
			return err
		}
		printlnf(cmd, "added user=%s group=%s", userID, groupID)
		return nil
	}
	_, err = admin.RemoveUserFromGroup(ctx, &identityv1.RemoveUserFromGroupRequest{
		UserId: userID, GroupId: groupID,
	})
	if err != nil {
		return err
	}
	printlnf(cmd, "removed user=%s group=%s", userID, groupID)
	return nil
}

func printGroup(cmd *cobra.Command, g *identityv1.Group) error {
	if g == nil {
		printlnf(cmd, "group=<nil>")
		return nil
	}
	printlnf(cmd, "id=%s name=%s parent=%s metadata=%v",
		g.GetId(), g.GetName(), g.GetParentId(), g.GetMetadata())
	return nil
}
