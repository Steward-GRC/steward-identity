# Data model

The identity service owns one Postgres database. Its schema is one baseline migration,
`migrations/0001_baseline.up.sql` (and `.down.sql`), applied with go-postgres's `Migrate`. Until
the first release the baseline stays the only migration.

| Table | Holds |
| --- | --- |
| `users` | accounts: email, names, time zone and locale, `external_subject` (the sign-in service's subject; empty for a local account until its first sign-in), `is_root`, `local_account`, the onboarding and email-verified flags, and the tombstone (`deleted_at`, `merged_into_user_id`) |
| `groups` | the group tree; a trigger refuses cycles, and names are unique among siblings |
| `group_membership` | memberships, each with its `source`: `manual`, or `idp-sync` for those an SSO connection's group mappings created |
| `group_managers` | local group-manager grants, one group each |
| `user_roles` | global roles, and author and approver scoped to a category |
| `user_idp_groups` | the group names the identity provider asserted for a user |
| `user_permissions`, `user_policy_overrides`, `break_glass_grants` | individual grants and time-boxed break-glass reveals |
| `otp_codes`, `user_email_otp`, `user_totp`, `user_webauthn_credentials`, `webauthn_sessions` | one-time codes (hashed), the encrypted authenticator secret, passkey public keys and ceremony state |
| `idp_connections`, `sso_domains`, `domain_verification`, `idp_group_mappings`, `sp_certificates` | SSO connections, their domains and verification, group mappings and the public signing certificates (private keys live in Kubernetes Secrets) |
| `merge_operations`, `merge_operation_steps` | account merges and their resumable steps |

`idp_connections.connection_alias` is the routing key the SSO broker (Ory Polis) knows a
connection by. A domain's sign-in method is `local` or `sso`.

## Not in this database

- **Sessions** live in Ory Kratos; identity lists and revokes them through the Kratos API.
- **Audit events** are written by go-outbox, in the same transaction as the change they record,
  to its own table `audit_outbox` (created by `Outbox.Migrate` at start-up, not by the baseline).
  The relay publishes each as a `steward.audit.v1.AuditEvent` to the `audit` exchange with the
  routing key `audit.<tier>`; sign-ins and session events are the `activity` tier, the rest
  `audit`. During act-as the event names the real admin, and the target is kept in the
  `impersonated_user_id` attribute.

Installs of the original service come over through `steward-migrate`, which maps the renamed
columns and tables.
