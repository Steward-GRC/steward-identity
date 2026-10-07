# Runbook

## Start-up

The service applies the baseline migration, creates the audit outbox table, connects to Postgres
and RabbitMQ, and serves gRPC. A bad setting stops it with every problem listed. Kratos, Polis,
core and the group cache are optional: without them the features that need them answer with a
coded error and everything else works.

## Probes

Readiness follows go-buildinfo's dependency checker. Each check has a 2-second timeout, and a result
is reused for 5 seconds.

| Dependency | Required | When it's down |
| --- | --- | --- |
| `postgres` | yes | Not ready: nothing can be read or written. |
| `rabbitmq` | no | Degraded, still ready: audit events wait in `audit_outbox` and go out when the broker is back; lifecycle notifications are skipped. |
| `valkey` | no, reported when `REDIS_ADDR` is set | Degraded, still ready: group lookups go to Postgres. |
| `kratos` | no, reported when `KRATOS_ADMIN_URL` is set | Degraded, still ready: local accounts, password resets, sessions and deletes answer coded "unavailable" errors. |
| `polis` | no, reported when `POLIS_ADMIN_URL` is set | Degraded, still ready: adding or changing SSO connections fails with `SSO_PROVIDER_UNREACHABLE`. |

- **HTTP on `PROBE_PORT` (8080):** `GET /livez` is 200 while the process is up and never checks a
  dependency. `GET /readyz` is 200 while ready and 503 while Postgres is down; its JSON body lists
  every dependency with its state and error class. There's no plain `/health`.
- **gRPC on `GRPC_PORT`:** `grpc.health.v1` with the service name `liveness` reports the process
  only. The empty name and `readiness` follow readiness. Every `Health/Check` answer carries
  `steward-version`, `steward-commit`, `steward-dep-<name>` (a dependency's version, where it has
  one) and `steward-depstate-<name>` (`ok`, `degraded` or `down`).
- The image takes `VERSION` and `COMMIT` build arguments; an unstamped build reports `dev`.
- Readiness recovers on its own once the dependency is back.

## SSO onboarding

An organisation's connection is set up by a site-admin through the gateway (or the
`IdentitySSOAdminService` directly):

1. `AddOrganization` creates the connection in Polis (tenant: the organisation's email domain;
   product: `POLIS_PRODUCT`) and the disabled row in identity. It never takes `enabled` from the
   caller.
2. `StartDomainVerification` returns the TXT record: name `_<VERIFY_TXT_PREFIX>.<domain>`, value
   `<VERIFY_TXT_PREFIX>=<token>`. The domain owner publishes it, then `VerifyDomain` looks it up.
   The token stays the same unless `rotate` is set.
3. Run a test sign-in through the gateway in test mode; it calls `RecordIdPTestResult`.
4. `ActivateOrganization` refuses until both gates are clear, then the domain routes to SSO:
   `Discover` answers `sso` with the connection alias.
5. On the first sign-in, `JitProvisionByEmail` creates the account (unless the connection's
   `jit_enabled` is off) and applies the connection's group mappings. The asserted groups replace
   the user's identity provider groups on every SSO sign-in.

The connection alias is a slug of the organisation name (or the domain) and is the live routing
key: `Discover` returns it, the sign-in page sends it back to the gateway, and the gateway passes
it to `JitProvisionByEmail`. Polis keys the connection on tenant and product; the alias isn't part
of any URL registered with Polis or the upstream identity provider. A rename changes the alias and
the organisation name together; a sign-in already in flight with the old alias is refused and the
user retries.

`ChangeOrgProtocol` sets the connection up again in Polis and resets both gates.
`DeleteOrganization` removes it from Polis and identity. The SAML signing certificate is managed
only when `SP_CERT_NAMESPACE` is set and the service runs in a cluster; its private key lives only
in the Kubernetes Secret.

## Act-as

The gateway forwards the signed-in user and, during act-as, the real admin (go-grpc-actor). Identity
believes them only from a verified caller with on-behalf access (the gateway, see
[service-to-service authentication](configuration.md#service-to-service-authentication)), checks admin rights
against its own roles for the subject, credits the admin in every audit event, and forwards both on
its calls to core, which also carry identity's own token. Password and second-factor changes, deletes, and role and permission changes are
refused during act-as with `ACT_AS_FORBIDDEN`.

## Common problems

| Symptom | Look at |
| --- | --- |
| Every admin call through the gateway is `ADMIN_AUTHZ_REQUIRED` | The subject lacks `site-admin`. |
| `Unavailable: workload verifier unavailable`, `/readyz` 503 with `jwks` down | No issuer key set has loaded. Check `WORKLOAD_OIDC_ISSUER`, the CA file and the bearer file: the API server answers 401 to a bearer with the `steward` audience, so the bearer must be the second projected token. |
| `Unauthenticated: no workload token` or `workload token rejected` | The caller sent no token, or one with the wrong audience, issuer or expiry, or from a service account outside `WORKLOAD_ALLOWED_SERVICEACCOUNTS`. Check the caller's `WORKLOAD_TOKEN_FILE` mount and identity's allow-list. |
| `PermissionDenied: caller not allowed on this method` | A verified caller isn't listed for the method; the refusal is audited as `rpc.denied`. |
| `identity-admin` is refused | The CLI certificate's SPIFFE ID must equal `IDENTITY_ADMIN_CLI_ID`, `AUDIT_USER` must be set, and `WORKLOAD_TOKEN_FILE` must name the pod's projected token. |
| `USER_DELETE_CHECKS_UNAVAILABLE` naming `approval_check` | `WORKFLOW_GRPC_ADDR` is unset or steward-workflow didn't answer: deletes stay refused rather than strand approvals. Disable the account to lock the user out. |
| Merge answers that a service isn't configured | `WORKFLOW_GRPC_ADDR` or `OBLIGATIONS_GRPC_ADDR` is unset. |
| `SESSIONS_UNAVAILABLE` or `SESSION_REVOKE_UNAVAILABLE` | `KRATOS_ADMIN_URL` and `steward-depstate-kratos`. Nothing was revoked. |
| `SSO_PROVIDER_UNREACHABLE` | `POLIS_ADMIN_URL`, `POLIS_API_KEY` and `steward-depstate-polis`; the log line with the same trace id has the cause. |
| No events reach audit | `steward-depstate-rabbitmq`, then the `audit` exchange and its binding; rows waiting in `audit_outbox` with status `pending` or `dead`. |

## Backups

Back up Postgres and `TOTP_ENC_KEY` together; without the key the stored authenticator secrets
can't be read. The SAML signing keys and Polis client secrets live in their Kubernetes Secrets.
