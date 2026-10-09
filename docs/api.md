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
`InvalidArgument`; a failed last-seen write is logged and the lookup still answers. Ory Polis brokers SAML and OIDC: an organisation's connection is created in Polis,
and its `connection_alias` is the routing key the gateway signs users in through. An OIDC
connection's client secret is write-only: `client_secret` on `AddOrganization`, `ChangeOrgProtocol`
and `UpdateIdPConnection`, or `secret_ref` naming a pre-created key; no response carries either
(see the [runbook](runbook.md#oidc-client-secrets)). `Organization.secret_reentry_required` says an
admin must enter the secret again.

`ResolveClaims` takes the subject the sign-in service issued (`external_subject`) and the sign-in's
claims as fields. With a `connection_alias`, `idp_groups` replaces the user's identity provider
groups and is matched against the connection's group mappings.

## Root admins and hard resets

There may be several root admins. `GrantRoot` and `RevokeRoot` add and remove one; both need a
root admin, the caller's step-up code (`RequestStepUpOtp`) and no act-as. The last root admin
can't lose the role, and a root admin can't be disabled, deleted or merged away until it's
revoked. `BootstrapRoot` makes only the first.

A hard reset of a module (only `compliance` today) takes two root admins:

1. `RequestHardReset` (module and reason) by one root admin. It waits `HARD_RESET_REQUEST_TTL`
   (24 hours) for approval, and a module has at most one open request.
2. `ApproveHardReset` by a different root admin. The approval is usable once, for
   `HARD_RESET_APPROVAL_TTL` (1 hour).
3. `ConsumeHardReset` by the module's own service (steward-reporting for `compliance`), calling
   as itself, just before it runs the reset. It answers with the request naming both admins.

`CancelHardReset` withdraws a pending or approved request; only the requester may.
`ListHardResetRequests` lists them for a root admin. Request, approve and cancel are refused during
act-as and from the admin CLI, since both people must be named. Each step is an audit event
crediting the admin (`hard_reset.requested`, `.approved`, `.cancelled`), or the service
(`hard_reset.consumed`); a request that runs out of time is recorded as `hard_reset.expired`.

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
