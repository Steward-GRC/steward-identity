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

The caller's identity travels in the go-grpc-actor metadata, never in a request field. During
act-as the actor carries the target as the subject and the real admin as the impersonator;
identity's audit events credit the admin and keep the target as `impersonated_user_id`, and its
own outbound calls forward both.

## Sign-in

Sign-in is Ory only. Ory Kratos holds local accounts, passwords and sessions: `CreateLocalUser`,
`ResetUserPassword`, `BootstrapRoot` and `ResetPasswordWithCode` write to Kratos, and
`ListUserSessions`, `RevokeSession`, `RevokeUserSessions` and `RevokeMySessions` read and revoke
Kratos sessions. Ory Polis brokers SAML and OIDC: an organisation's connection is created in Polis,
and its `connection_alias` is the routing key the gateway signs users in through.

`ResolveClaims` takes the subject the sign-in service issued (`external_subject`) and the sign-in's
claims as fields. With a `connection_alias`, `idp_groups` replaces the user's identity provider
groups and is matched against the connection's group mappings.

## Errors

Coded errors carry a `google.rpc.ErrorInfo` with the domain `identity`; see
[error-codes.md](error-codes.md).
