-- Copyright 2026 The Steward Authors
-- SPDX-License-Identifier: Apache-2.0

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  external_subject    TEXT NOT NULL,
  email               TEXT NOT NULL,
  name                TEXT NOT NULL DEFAULT '',
  fcm_token           TEXT NOT NULL DEFAULT '',
  enabled             BOOLEAN NOT NULL DEFAULT TRUE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  is_root             BOOLEAN NOT NULL DEFAULT FALSE,
  local_account       BOOLEAN NOT NULL DEFAULT FALSE,
  username            TEXT,
  onboarding_complete BOOLEAN NOT NULL DEFAULT FALSE,
  terms_accepted_at   TIMESTAMPTZ,
  first_name          TEXT NOT NULL DEFAULT '',
  last_name           TEXT NOT NULL DEFAULT '',
  timezone            TEXT NOT NULL DEFAULT '',
  locale              TEXT NOT NULL DEFAULT '',
  deleted_at          TIMESTAMPTZ,
  email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
  email_verified_at   TIMESTAMPTZ,
  merged_into_user_id UUID REFERENCES users(id)
);

CREATE INDEX users_email_idx ON users (lower(email));
-- At most one root admin.
CREATE UNIQUE INDEX users_single_root_idx ON users (is_root) WHERE is_root;
CREATE UNIQUE INDEX users_lower_username_uniq ON users (lower(username)) WHERE username IS NOT NULL;
-- Local accounts are created with an empty subject until their first sign-in
-- links one, so only non-empty subjects are unique.
CREATE INDEX users_lower_email_local_adopt ON users (lower(email))
  WHERE local_account = true AND external_subject = '';
CREATE UNIQUE INDEX users_external_subject_key ON users (external_subject) WHERE external_subject <> '';
CREATE INDEX users_merged_into_idx ON users (merged_into_user_id);

CREATE TABLE groups (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  parent_id   UUID REFERENCES groups(id) ON DELETE RESTRICT,
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Names are unique among siblings; root groups get their own partial index.
CREATE UNIQUE INDEX groups_parent_name_idx ON groups (parent_id, name) WHERE parent_id IS NOT NULL;
CREATE UNIQUE INDEX groups_root_name_idx ON groups (name) WHERE parent_id IS NULL;
CREATE INDEX groups_parent_id_idx ON groups (parent_id);

CREATE OR REPLACE FUNCTION groups_no_cycle() RETURNS TRIGGER AS $$
DECLARE
  cur UUID := NEW.parent_id;
BEGIN
  WHILE cur IS NOT NULL LOOP
    IF cur = NEW.id THEN
      RAISE EXCEPTION 'group cycle: % cannot be its own ancestor', NEW.id;
    END IF;
    SELECT parent_id INTO cur FROM groups WHERE id = cur;
  END LOOP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER groups_no_cycle_trigger
  BEFORE INSERT OR UPDATE OF parent_id ON groups
  FOR EACH ROW EXECUTE FUNCTION groups_no_cycle();

CREATE TABLE group_membership (
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_id          UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  added_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  added_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
  -- 'manual' for admin, self and group-manager grants; 'idp-sync' for
  -- memberships an SSO connection's group mappings created, which group
  -- managers can't change.
  source            TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','idp-sync')),
  PRIMARY KEY (user_id, group_id)
);

CREATE INDEX group_membership_group_id_idx ON group_membership (group_id);

-- reader is implicit and never stored; author and approver are scoped to a
-- category, every other role is global.
CREATE TABLE user_roles (
  user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role                TEXT NOT NULL,
  granted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  granted_by_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
  scope_category      TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (user_id, role, scope_category),
  CONSTRAINT user_roles_role_check
    CHECK (role IN ('author','approver','site-admin','template-admin','compliance-admin')),
  CONSTRAINT user_roles_scope_check CHECK (
    (role IN ('author','approver') AND scope_category <> '')
    OR (role NOT IN ('author','approver') AND scope_category = '')
  )
);

CREATE INDEX user_roles_role_idx ON user_roles (role);

-- Group names the identity provider asserted for the user.
CREATE TABLE user_idp_groups (
  user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  idp_group_name TEXT NOT NULL,
  synced_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, idp_group_name)
);

CREATE TABLE user_policy_overrides (
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  policy_number TEXT NOT NULL,
  effect        TEXT NOT NULL CHECK (effect IN ('allow','deny')),
  PRIMARY KEY (user_id, policy_number)
);

CREATE TABLE user_permissions (
  user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  permission         TEXT NOT NULL CHECK (permission IN ('policy.read_sensitive')),
  granted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  granted_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, permission)
);

CREATE TABLE break_glass_grants (
  id            BIGSERIAL PRIMARY KEY,
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  policy_number TEXT NOT NULL,
  reason        TEXT NOT NULL,
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX bgg_active_idx ON break_glass_grants (user_id, policy_number, expires_at);

-- One-time codes for local accounts: password reset and sign-in codes. Only
-- the sha256 of a code is stored; rows are single-use, short-lived and
-- attempt-limited.
CREATE TABLE otp_codes (
  id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT        NOT NULL,
  code_hash   TEXT        NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  attempts    INT         NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX otp_codes_user_purpose_idx ON otp_codes (user_id, purpose, created_at DESC);

-- The authenticator secret is stored only encrypted (AES-256-GCM); a NULL
-- confirmed_at is a pending enrolment.
CREATE TABLE user_totp (
  user_id          UUID        NOT NULL PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  encrypted_secret TEXT        NOT NULL,
  confirmed_at     TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  label            TEXT        NOT NULL DEFAULT ''
);

-- Emailed second-factor codes, keyed by user id; same posture as otp_codes.
CREATE TABLE user_email_otp (
  id          UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT        NOT NULL,
  code_hash   TEXT        NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  attempts    INT         NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX user_email_otp_user_purpose_idx ON user_email_otp (user_id, purpose, created_at DESC);

-- Passkeys: public key material only.
CREATE TABLE user_webauthn_credentials (
  credential_id   TEXT        NOT NULL PRIMARY KEY,
  user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key      BYTEA       NOT NULL,
  sign_count      BIGINT      NOT NULL DEFAULT 0,
  aaguid          BYTEA,
  transports      TEXT[]      NOT NULL DEFAULT '{}',
  backup_eligible BOOLEAN     NOT NULL DEFAULT false,
  backup_state    BOOLEAN     NOT NULL DEFAULT false,
  label           TEXT        NOT NULL DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at    TIMESTAMPTZ
);
CREATE INDEX user_webauthn_credentials_user_idx ON user_webauthn_credentials (user_id, created_at);

-- Short-lived, single-use WebAuthn ceremony state.
CREATE TABLE webauthn_sessions (
  session_id UUID        NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose    TEXT        NOT NULL,
  data_json  TEXT        NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webauthn_sessions_user_purpose_idx ON webauthn_sessions (user_id, purpose);

CREATE TABLE idp_connections (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_name         TEXT NOT NULL,
  protocol         TEXT NOT NULL CHECK (protocol IN ('oidc','saml')),
  -- The routing key the SSO broker knows the connection by.
  connection_alias TEXT NOT NULL UNIQUE,
  display_name     TEXT NOT NULL DEFAULT '',
  -- Non-secret settings only; secrets are referenced by secret_ref.
  config           JSONB NOT NULL DEFAULT '{}'::jsonb,
  secret_ref       TEXT NOT NULL DEFAULT '',
  enabled          BOOLEAN NOT NULL DEFAULT FALSE,
  test_passed_at   TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  jit_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  allow_local      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE sso_domains (
  domain        TEXT PRIMARY KEY,
  method        TEXT NOT NULL CHECK (method IN ('local','sso')),
  connection_id UUID REFERENCES idp_connections(id) ON DELETE RESTRICT,
  verified      BOOLEAN NOT NULL DEFAULT FALSE,
  verified_at   TIMESTAMPTZ,
  created_by    TEXT NOT NULL DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (method <> 'sso' OR connection_id IS NOT NULL)
);

-- Maps by group id: names are unique only among siblings.
CREATE TABLE idp_group_mappings (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connection_id         UUID NOT NULL REFERENCES idp_connections(id) ON DELETE CASCADE,
  idp_group_claim_value TEXT NOT NULL,
  target_group_id       UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  UNIQUE (connection_id, idp_group_claim_value)
);

CREATE TABLE domain_verification (
  domain      TEXT PRIMARY KEY REFERENCES sso_domains(domain) ON DELETE CASCADE,
  token       TEXT NOT NULL,
  method      TEXT NOT NULL DEFAULT 'dns-txt' CHECK (method IN ('dns-txt','email')),
  verified_at TIMESTAMPTZ
);

-- Public certificates only; each private key lives in a Kubernetes Secret
-- named by secret_ref.
CREATE TABLE sp_certificates (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  serial     TEXT NOT NULL UNIQUE,
  cert_pem   TEXT NOT NULL,
  secret_ref TEXT NOT NULL,
  active     BOOLEAN NOT NULL DEFAULT FALSE,
  not_after  TIMESTAMPTZ NOT NULL,
  retired_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX sp_certificates_single_active_idx ON sp_certificates (active) WHERE active;

-- One row per merge; a re-run with the same idempotency key resumes it.
CREATE TABLE merge_operations (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key  TEXT        NOT NULL UNIQUE,
  source_user_id   UUID        NOT NULL REFERENCES users(id),
  target_user_id   UUID        NOT NULL REFERENCES users(id),
  actor_user_id    UUID        REFERENCES users(id),
  actor_external   TEXT        NOT NULL DEFAULT '',
  status           TEXT        NOT NULL DEFAULT 'in_progress'
                     CHECK (status IN ('in_progress','partial','completed','failed')),
  counts           JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE merge_operation_steps (
  merge_operation_id UUID        NOT NULL REFERENCES merge_operations(id) ON DELETE CASCADE,
  step               TEXT        NOT NULL,
  status             TEXT        NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','completed','failed','skipped')),
  detail             TEXT        NOT NULL DEFAULT '',
  error              TEXT        NOT NULL DEFAULT '',
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (merge_operation_id, step)
);

-- A user manages one group's manual memberships through a row here.
CREATE TABLE group_managers (
  user_id             UUID        NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
  group_id            UUID        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  granted_by_user_id  UUID        REFERENCES users(id) ON DELETE SET NULL,
  granted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, group_id)
);
CREATE INDEX group_managers_group_id_idx ON group_managers (group_id);
