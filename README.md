# steward-identity 🪪

> 🧭 Users, groups, roles, sign-in factors and SSO connections for Steward

The identity service answers who a user is for every other Steward service, and runs the parts of
sign-in Steward owns.

- **People:** users, the group tree and its managers, global and category-scoped roles, the root
  admin, per-policy overrides, break glass, onboarding and profiles.
- **Sign-in:** Ory only. Kratos holds local accounts, passwords and sessions; Polis brokers SAML and
  OIDC for each organisation's SSO connection, with domain verification, connection tests, group
  mappings and just-in-time accounts.
- **Second factors:** an authenticator app, emailed codes and passkeys, with identity as the
  WebAuthn relying party.
- **Lifecycle:** merge two accounts (a resumable saga) and delete one, each with a read-only preview.
- **Act-as:** the real admin is carried on every call and credited in every audit event.

It calls steward-core for merge and the delete checks, and publishes steward-audit's `AuditEvent`
through a transactional outbox.

## 🚀 Run

```bash
cp .env.example .env   # a local Postgres and RabbitMQ; Kratos and Polis are optional
task run
```

Or build the image with `docker build --build-arg VERSION=dev --build-arg COMMIT=$(git rev-parse HEAD) -t steward-identity .`.
The image holds the service and the `identity-admin` CLI. Settings are in
[configuration](docs/configuration.md); probes and common problems are in the
[runbook](docs/runbook.md).

## 📚 Docs

- [API](docs/api.md): the gRPC services, events and calling other services.
- [Configuration](docs/configuration.md).
- [Runbook](docs/runbook.md), including SSO onboarding.
- [Data model](docs/data-model.md).
- [Admin CLI](docs/admin-cli.md).
- [Error codes](docs/error-codes.md).

## 🛠 Develop

```bash
task build       # go build ./...
task test        # go test ./... (the store and handler tests start Postgres with testcontainers)
task test-race   # the same with the race detector
task lint        # gofmt check + golangci-lint + yamllint
task proto       # fetch the pinned callee protos, buf lint, regenerate gen/
task license     # check Apache-2.0 headers (golic)
```

Set `DATABASE_TEST_DSN` to run the database tests against an existing Postgres instead of a
container.

## 🙏 Acknowledgements

Steward was originally written by [@Bugs5382](https://github.com/Bugs5382).

## ⚖️ License

Apache-2.0 (c) 2026 The Steward Authors
