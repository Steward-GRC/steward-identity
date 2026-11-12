-- Copyright 2026 The Steward Authors
-- SPDX-License-Identifier: Apache-2.0

DROP INDEX IF EXISTS users_single_root_idx;
CREATE INDEX IF NOT EXISTS users_root_idx ON users (id) WHERE is_root;
