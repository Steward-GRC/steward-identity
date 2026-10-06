# Configuration

Every setting is an environment variable, read once at start-up. A bad value stops the service
with every problem listed; values never appear in the errors.

## Required

| Variable | Meaning |
| --- | --- |
| `DATABASE_DSN` | Postgres. |
| `RABBITMQ_URL` | RabbitMQ: the audit outbox relay and the lifecycle events publish here. |

## Service

| Variable | Default | Meaning |
| --- | --- | --- |
| `MIGRATE_DSN` | `DATABASE_DSN` | A direct connection for migrations, when the main DSN goes through a pooler. |
| `MIGRATIONS_DIR` | `migrations` | The SQL migrations; the image sets `/migrations`. |
| `GRPC_PORT` | `9090` | gRPC. |
| `PROBE_PORT` | `8080` | Plain HTTP for `/livez` and `/readyz`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OpenTelemetry collector, `host:port`. |
| `LOG_LEVEL`, `LOG_FORMAT` | | go-log's level and format. |

## Callers and mTLS

| Variable | Default | Meaning |
| --- | --- | --- |
| `WORKLOAD_AUTH` | enabled | `disabled` turns caller authentication off, for local runs only. Nothing else turns it off, and it can't be combined with `WORKLOAD_OIDC_*`. |
| `WORKLOAD_OIDC_ISSUER` | required unless disabled | The cluster's service-account token issuer, an `https` URL that must equal the token's `iss`. |
| `WORKLOAD_OIDC_JWKS_URL` | discovered | The issuer's key set, when it isn't at the `jwks_uri` of `<issuer>/.well-known/openid-configuration`. `https` only. |
| `WORKLOAD_OIDC_CA_FILE` | system roots | Extra PEM CA trusted for the discovery and key set fetch (the namespace's `kube-root-ca.crt`). |
| `WORKLOAD_OIDC_BEARER_FILE` | empty | A token sent on the discovery and key set fetch, re-read on every fetch: a second projected token with the API server's default audience, not the `steward` caller token. |
| `WORKLOAD_AUDIENCE` | `steward` | The audience a caller's token must carry. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | required unless disabled | Comma list of `<namespace>/<serviceaccount>` that may call identity at all: the gateway, workflow, obligations, reporting, collab and identity itself (for `identity-admin`). |
| `WORKLOAD_TOKEN_FILE` | `/var/run/secrets/steward/token` while authentication is on | Identity's own projected token (audience `steward`), sent to core on every call and re-read each time. An unreadable file stops the boot. |
| `GRPC_TLS_CERT_FILE`, `GRPC_TLS_KEY_FILE`, `GRPC_TLS_CLIENT_CA_FILE` | empty | Serve mTLS (TLS 1.3, client certificates required). Set all three or none. Transport only: it grants no caller any trust. |
| `IDENTITY_ADMIN_CLI_ID` | empty | The SPIFFE ID of the `identity-admin` CLI's client certificate. Needs mTLS. Empty gives the CLI no access to the admin services. |

## Service-to-service authentication

Every call except `grpc.health.v1` and server reflection must carry the calling service's projected
service-account token (audience `steward`) as `authorization: Bearer <token>`. Identity verifies it
against the issuer's key set (signature, issuer, audience, expiry), maps `<namespace>/steward-<name>`
to the caller `<name>`, and checks the per-method allow-list in `internal/server/callers.go`:

| Caller | Methods | Access |
| --- | --- | --- |
| `gateway` | the sign-in steps and the read, admin and SSO admin methods it serves | on behalf of the signed-in user |
| `workflow`, `reporting`, `collab` | `GetUser` | as itself |
| `obligations` | `GetUser`, `ListAllUsers`, `ResolveEmail`, `ResolveFCMToken` | as itself |
| `identity` (`identity-admin` in the identity pod) | the CLI's read and admin methods | as itself; the admin methods also need the CLI certificate (`IDENTITY_ADMIN_CLI_ID`) |

A method no caller uses is refused to everyone.

- **Refusals:** a missing or rejected token (wrong issuer or audience, expired, or a service account
  outside `WORKLOAD_ALLOWED_SERVICEACCOUNTS`) is `Unauthenticated`; a verified caller the method
  doesn't list is `PermissionDenied`. Every refusal is logged and audited as `rpc.denied`, with the
  caller (or `unauthenticated`) as the actor, never a user the call claimed.
- **Act-as:** a forwarded actor (go-grpc-actor) is believed only from a caller with on-behalf access.
  A caller that acts as itself has its forwarded actor dropped.
- **Fail closed:** while no key set has loaded (the issuer unreachable or refusing the fetch), every
  call that needs a token is refused with `Unavailable`, and readiness reports `jwks` as a failing
  required dependency.
- **Off switch:** with `WORKLOAD_AUTH=disabled` identity logs a warning at start-up and every five
  minutes, trusts no forwarded actor, and readiness reports `workloadauth` degraded. With neither
  `WORKLOAD_OIDC_ISSUER` nor `WORKLOAD_AUTH=disabled`, identity doesn't start.
- `internal/workloadauth` is a byte-identical copy of steward-core's, pinned by `STEWARD_CORE_REF` in
  `proto-refs.env` and compared in CI by `scripts/workloadauth-check.sh`; change it in steward-core
  first.

## Sign-in

| Variable | Default | Meaning |
| --- | --- | --- |
| `KRATOS_ADMIN_URL` | empty | Ory Kratos admin API. Empty turns off local accounts, password resets and session management: they answer `LOCAL_ACCOUNTS_UNAVAILABLE`, `SESSIONS_UNAVAILABLE` or `SESSION_REVOKE_UNAVAILABLE`. |
| `KRATOS_SCHEMA_ID` | `default` | The identity schema new local accounts get. It needs the traits `email` (the password and recovery identifier), `username` and `name`. |
| `POLIS_ADMIN_URL`, `POLIS_API_KEY` | empty | Ory Polis admin API and its key. Needed to add or change an SSO connection. |
| `POLIS_PRODUCT` | `steward` | The Polis product every connection lives under. |
| `GATEWAY_BASE_URL` | `http://localhost:5173` | Where Polis sends users back: `<base>/auth/sso/callback`, with `<base>/*` allowed. |
| `LOGIN_2FA_ENABLED` | `false` | Local sign-in also needs an emailed code. |
| `TOTP_ENC_KEY` | empty | 32 bytes, hex or base64: encrypts stored authenticator secrets. Keep it with the database backups. |
| `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_ORIGINS`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_USER_VERIFICATION` | `localhost`, `http://localhost:5173`, `Steward`, `preferred` | The passkey relying party. |
| `BREAK_GLASS_DURATION` | `15m` | How long a break-glass reveal lasts. |
| `SESSION_LAST_SEEN_THROTTLE` | `1m` | How often a sign-in session's last-seen time moves while it is in use. |

## SSO connections

| Variable | Default | Meaning |
| --- | --- | --- |
| `VERIFY_TXT_PREFIX` | `steward-verify` | The domain verification TXT record is `_<prefix>.<domain>` with the value `<prefix>=<token>`. |
| `DOMAIN_RECHECK_INTERVAL` | `6h` | How often verified domains are checked again. |
| `SP_CERT_SECRET_NAME`, `SP_CERT_NAMESPACE` | `identity-sp-cert`, `POD_NAMESPACE` | The Kubernetes Secret holding the SAML signing keys. |
| `POLIS_SECRET_NAME` | `identity-polis-secrets` | The Kubernetes Secret holding each connection's Polis client secret. |
| `SP_CERT_TTL_DAYS`, `SP_CERT_OVERLAP_HOURS` | `365`, `48` | Signing certificate lifetime, and how long the old one keeps serving after a rotation. |

## Other services and email

| Variable | Default | Meaning |
| --- | --- | --- |
| `CORE_GRPC_ADDR` | empty | steward-core, for merge and the delete checks. Empty makes those checks fail closed with `USER_DELETE_CHECKS_UNAVAILABLE`. |
| `REDIS_ADDR`, `REDIS_PASSWORD` | empty | Valkey or Redis for the identity provider group cache. Off when unset. |
| `IDP_GROUPS_CACHE_TTL` | `1m` | How long a user's cached groups are kept. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `SMTP_TLS`, `SMTP_TLS_INSECURE` | go-email's local defaults | The relay one-time codes go through. |
| `OTP_DEV_ECHO` | `false` | Logs one-time codes. Local development only. |
