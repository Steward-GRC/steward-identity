-- Copyright 2026 The Steward Authors
-- SPDX-License-Identifier: Apache-2.0

-- Exactly one root at a time. The baseline allowed several, so first demote
-- all but one: keep the root with the oldest site-admin grant, else the oldest
-- account. The demoted users keep their site-admin role and stay enabled.
--
-- Audit rows (root.revoked) cannot be written from here: the audit outbox
-- table is created by the service at start-up, after migrations run. Each
-- demotion is raised as a NOTICE in the migration log instead.
DO $$
DECLARE
  demoted RECORD;
BEGIN
  FOR demoted IN
    WITH ranked AS (
      SELECT u.id,
             row_number() OVER (
               ORDER BY coalesce(
                          (SELECT min(r.granted_at) FROM user_roles r
                            WHERE r.user_id = u.id AND r.role = 'site-admin' AND r.scope_category = ''),
                          'infinity'::timestamptz),
                        u.created_at, u.id) AS rn
        FROM users u
       WHERE u.is_root
    )
    SELECT id FROM ranked WHERE rn > 1
  LOOP
    UPDATE users SET is_root = false, updated_at = now() WHERE id = demoted.id;
    RAISE NOTICE 'single root: demoted user % (kept the oldest root)', demoted.id;
  END LOOP;
END $$;

-- The unique index replaces the baseline's plain one.
DROP INDEX IF EXISTS users_root_idx;
CREATE UNIQUE INDEX users_single_root_idx ON users ((true)) WHERE is_root;
