# Admin CLI

`identity-admin` is the operators' command line for the identity service, built from
`cmd/identity-admin` into the same image as the server. It calls `IdentityAdminService` and
`IdentityReadService` over mTLS and prints each answer as `key=value` pairs, so scripts can grep
them.

## Commands

| Command | What it does |
| --- | --- |
| `user list [--email-contains S] [--enabled \| --disabled] [--limit N]` | Pages through users by email substring |
| `user show <email-or-id>` | One user |
| `user enable <email-or-id>`, `user disable <email-or-id>` | Enables or disables a user |
| `user grant-role <email-or-id> <role>`, `user revoke-role <email-or-id> <role>` | Global roles: admin, site-admin, template-admin, compliance-admin |
| `group list [--parent ID] [--descendants] [--limit N]` | Root groups, or the groups under a parent |
| `group show <id>` | One group |
| `group create <name> [--parent ID]`, `group rename <id> <name>`, `group delete <id>` | Group lifecycle |
| `group add-member <group-id> <email-or-id>`, `group remove-member <group-id> <email-or-id>` | Memberships |
| `group set-parent <id> <parent-id>` | Moves a group; an empty parent makes it a root group |
| `bootstrap initial-admin --subject S --email E` | Creates the first admin; does nothing once one exists |

An email argument must match exactly one user. Groups are addressed by id only.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `AUDIT_USER` | none (required for admin calls) | The operator's label, sent with every admin call |
| `IDENTITY_GRPC_ADDR` | `identity:9090` | The identity service |
| `IDENTITY_ADMIN_CERT_DIR` | `/var/run/identity-admin-cert` | Holds `tls.crt`, `tls.key` and `ca.crt` |
| `IDENTITY_ADMIN_CA_FILE` | `<cert dir>/ca.crt` | The CA the server certificate must chain to |
| `IDENTITY_INSECURE` | unset | `1` dials without TLS, for local development only |

## Identity and audit

- The CLI presents its client certificate over TLS 1.3. The server lets a call use the admin
  services when the verified client certificate's SPIFFE ID equals `IDENTITY_ADMIN_CLI_ID`; with
  that setting empty, the CLI has no admin access.
- Every admin call carries the operator label in the `x-audit-operator` gRPC metadata. The server
  records it as the actor of the audit event. The CLI refuses to send an admin call without
  `AUDIT_USER`.
- A forwarded actor (go-grpc-actor) on the context is passed on, and each call is traced through
  go-otel.
