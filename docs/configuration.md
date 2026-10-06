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
| `GRPC_TLS_CERT_FILE`, `GRPC_TLS_KEY_FILE`, `GRPC_TLS_CLIENT_CA_FILE` | empty | Serve mTLS (TLS 1.3, client certificates required). Set all three or none. |
| `IDENTITY_TRUSTED_CALLERS` | empty | Comma-separated SPIFFE IDs whose forwarded actor (go-grpc-actor) is believed. Needs mTLS. Empty ignores every forwarded actor, so admin calls through the gateway are refused. |
| `IDENTITY_ADMIN_CLI_ID` | empty | The SPIFFE ID of the `identity-admin` CLI's client certificate. Needs mTLS. Empty gives the CLI no access. |

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
