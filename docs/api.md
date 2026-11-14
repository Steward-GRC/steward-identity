# API

The identity service speaks gRPC. The protos live in `proto/steward/identity/v1` (package
`steward.identity.v1`) and the Go stubs are committed in `gen/go/steward/identity/v1`. Every RPC
has its own request and response message, and `buf lint` runs the plain `STANDARD` rules.

| File | Service | Who calls it |
| --- | --- | --- |
| `read.proto` | `IdentityReadService` | every internal service: who a user is, their groups, and the unauthenticated sign-in steps (password reset codes, sign-in codes, second factors, discovery) |
| `admin.proto` | `IdentityAdminService` | the gateway for site-admins and the admin CLI: users, roles, groups, sessions, merge and delete; a few self-service calls act on the calling user |
| `sso_admin.proto` | `IdentitySSOAdminService` | the same callers: organisations' SSO connections, domain verification, group mappings and the signing certificate |
| `types.proto` | | the messages the services share |

## Callers and the actor

Every call except health and reflection carries the calling service's workload token, and each
method admits only the callers listed in
[service-to-service authentication](configuration.md#service-to-service-authentication). The
user's identity travels in the go-grpc-actor metadata, never in a request field, and is believed
only from a caller with on-behalf access (the gateway). During
act-as the actor carries the target as the subject and the real admin as the impersonator;
identity's audit events credit the admin and keep the target as `impersonated_user_id`, and its
own outbound calls forward both.

## Sign-in

Sign-in is Ory only. Ory Kratos holds local accounts, passwords and sessions: `CreateLocalUser`,
`ResetUserPassword`, `BootstrapRoot` and `ResetPasswordWithCode` write to Kratos, and
`ListUserSessions`, `RevokeSession`, `RevokeUserSessions` and `RevokeMySessions` read and revoke
Kratos sessions. Kratos keeps no last-use time, so identity records one itself: when the gateway
calls `GetUser` for a signed-in request it passes the Kratos session id as `session_id`, and
identity stores that session as seen, at most once per `SESSION_LAST_SEEN_THROTTLE` per replica (a
conditional update keeps replicas from writing more often). `ListUserSessions` returns it as
`Session.last_seen_at` (RFC 3339; empty for a session never seen). A malformed `session_id` is
`InvalidArgument`; a failed last-seen write is logged and the lookup still answers. `ChangeMyPassword` changes the caller's own password (the forwarded actor, never a request field; refused
during act-as). Kratos's admin API sets a password without applying its password policy and cannot
check a current one, so identity uses Kratos's public API (`KRATOS_PUBLIC_URL`): a sign-in flow with
the current password proves it (`CURRENT_PASSWORD_WRONG` otherwise), then the settings flow on that
session sets the new one under Kratos's own policy (`PASSWORD_TOO_WEAK` when it refuses), and the
short-lived session is signed out. An account with no local password answers `NO_LOCAL_PASSWORD`,
and an unreachable or unconfigured Kratos `PASSWORD_CHANGE_UNAVAILABLE`. A change is audited as
`user.password.changed` and a refused attempt as `user.password.change_failed` (with a `reason`);
neither payload, nor any log line, carries a password or a token. Ory Polis brokers SAML and OIDC: an organisation's connection is created in Polis,
and its `connection_alias` is the routing key the gateway signs users in through. An OIDC
connection's client secret is write-only: `client_secret` on `AddOrganization`, `ChangeOrgProtocol`
and `UpdateIdPConnection`, or `secret_ref` naming a pre-created key; no response carries either
(see the [runbook](runbook.md#oidc-client-secrets)). `Organization.secret_reentry_required` says an
admin must enter the secret again.

`ResolveClaims` takes the subject the sign-in service issued (`external_subject`) and the sign-in's
claims as fields. With a `connection_alias`, `idp_groups` replaces the user's identity provider
groups and is matched against the connection's group mappings.

## Directory group names

`ListIdpGroupNames` (`IdentityReadService`) lists the directory (identity provider) group names
identity knows, so the gateway's category-rule group picker can offer real names instead of free
text. The answer is the distinct union of every user's IdP groups (`user_idp_groups`) and the claim
values in the SSO group mappings (`idp_group_mappings`, across all connections), sorted in byte
order (upper case before lower). It carries names only, never which user holds one.

| Field | Meaning |
| --- | --- |
| `prefix` | optional; trimmed, at most 256 bytes (`InvalidArgument` beyond that); matched at the start of the name, case-insensitively; a percent sign or underscore is text, not a pattern |
| `limit` | 50 when unset, at most 200 |
| `names` | the matching names, up to `limit` |
| `truncated` | true when more names matched than `limit` allowed; narrow the prefix to see them |

Only the gateway may call it. Like `SearchGroups`, identity does not decide who may ask: the gateway
allows group managers and template admins. Logs carry counts and the prefix length, never a name.

## Root admins and hard resets

There is exactly one root admin at a time (a unique index on `users.is_root` enforces it).
`TransferRoot(to_user_id, otp)` moves the role: the new root is enabled and gets site-admin, and the
old root becomes an ordinary site-admin in the same step. Sessions are not revoked. Only the root
may call it, with the caller's step-up code (`RequestStepUpOtp`), never during act-as and never from
the admin CLI (no actor, `PERMISSION_DENIED`). The target must be a live account other than the
caller. The audit event is `root.transferred` (actor: the old root, subject: the new root,
`from_user_id` in the payload). The root can't be disabled, deleted, merged away or stripped of
site-admin; to retire the account, transfer root first. `BootstrapRoot` makes only the first.

`GrantRoot` and `RevokeRoot` are deprecated stubs, kept so the proto stays wire-compatible. They change nothing and always answer `UNIMPLEMENTED`; `TransferRoot` is the only way to change the root.

Migration `0002_single_root` keeps one root where an older database had several (the oldest
site-admin grant, else the oldest account) and clears `is_root` on the rest, who stay site-admins.
It cannot write audit rows, since the audit outbox table is created at start-up after migrations,
so each demotion is a `NOTICE` in the migration log instead.

A hard reset of a module (only `compliance` today) takes two different people: the root admin asks
and a different site-admin approves. The root cannot approve its own request, and there is never a
second root.

1. `RequestHardReset` (module and reason) by the root admin. It waits `HARD_RESET_REQUEST_TTL`
   (24 hours) for approval, and a module has at most one open request.
2. `ApproveHardReset` by an active site-admin who is not the requester: the account is enabled and
   not deleted and holds the global site-admin right in the database (a session claim is not enough).
   The approval is usable once, for `HARD_RESET_APPROVAL_TTL` (1 hour).
3. `ConsumeHardReset` by the module's own service (steward-reporting for `compliance`), calling
   as itself, just before it runs the reset. It answers with the request naming both people
   (`requested_by` and `approved_by`, never equal). It re-checks that the requester is still the
   root admin and the approver is still an active site-admin, and refuses (`FAILED_PRECONDITION`,
   the request is left as it is) when either has changed since.

A request that is not approved in time, or an approval not used in time, expires and is refused with
`FAILED_PRECONDITION`. A non-root requester or an approver who is not an active site-admin gets
`PERMISSION_DENIED`, so does the requester approving its own request.

`CancelHardReset` withdraws a pending or approved request; only the requester may.
`ListHardResetRequests` lists them for the root admin or any active site-admin (who need to see a
request to approve it). Request, approve and cancel are refused during act-as and from the admin CLI,
since both people must be named. Each step is an audit event crediting the person
(`hard_reset.requested`, `.approved`, `.cancelled`), or the service (`hard_reset.consumed`); a request
that runs out of time is recorded as `hard_reset.expired`.

## Errors

Coded errors carry a `google.rpc.ErrorInfo` with the domain `identity`; see
[error-codes.md](error-codes.md).

## Events

| Exchange | Routing key | Body | When |
| --- | --- | --- | --- |
| `audit` | `audit.audit`, `audit.activity` | `steward.audit.v1.AuditEvent`, protobuf | every change and sign-in, written to the go-outbox table in the same transaction and relayed at least once |
| `jobs` | `sso.lifecycle` | JSON `{event, vars}` | an SSO account provisioned, access granted, a break-glass sign-in |
| `jobs` | `account.created` | JSON | every genuine account create |
| `jobs` | `membership.changed` | JSON | a user left groups (obligations purges acknowledgements they no longer owe) |

## Calling other services

Identity never imports another service's Go module. `proto-refs.env` pins each callee at a commit
on its `main`; `scripts/proto-generate.sh` fetches those protos into the git-ignored `.protos/` and
generates stubs under `gen/go/thirdparty/`.

| Callee | Pin | Used for |
| --- | --- | --- |
| steward-core | `STEWARD_CORE_REF` | merge (re-own policies), the delete checks (purge category rules) and the delete preview (owned policies, rules a delete would remove) |
| steward-audit | `STEWARD_AUDIT_REF` | the `AuditEvent` message published to the `audit` exchange |
| steward-workflow | `STEWARD_WORKFLOW_REF` | pending approvals (the delete refusal and the delete preview, `ListPendingTasks`) and re-pointing approvals in a merge (`ReassignUserWorkflowItems`) |
| steward-obligations | `STEWARD_OBLIGATIONS_REF` | moving acknowledgements in a merge and its preview (`TransferAcknowledgments`) |

A callee whose address isn't set is treated as unavailable: the delete checks answer
`USER_DELETE_CHECKS_UNAVAILABLE` and merges refuse, rather than strand records.

Every outbound connection carries identity's own workload token (`WORKLOAD_TOKEN_FILE`) and the
caller and the act-as admin (go-grpc-actor's client interceptors).
