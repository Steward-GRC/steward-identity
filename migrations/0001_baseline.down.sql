-- Copyright 2026 The Steward Authors
-- SPDX-License-Identifier: Apache-2.0

DROP TABLE IF EXISTS group_managers;
DROP TABLE IF EXISTS merge_operation_steps;
DROP TABLE IF EXISTS merge_operations;
DROP TABLE IF EXISTS sp_certificates;
DROP TABLE IF EXISTS domain_verification;
DROP TABLE IF EXISTS idp_group_mappings;
DROP TABLE IF EXISTS sso_domains;
DROP TABLE IF EXISTS idp_connections;
DROP TABLE IF EXISTS webauthn_sessions;
DROP TABLE IF EXISTS user_webauthn_credentials;
DROP TABLE IF EXISTS user_email_otp;
DROP TABLE IF EXISTS user_totp;
DROP TABLE IF EXISTS otp_codes;
DROP TABLE IF EXISTS break_glass_grants;
DROP TABLE IF EXISTS user_permissions;
DROP TABLE IF EXISTS user_policy_overrides;
DROP TABLE IF EXISTS user_idp_groups;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS group_membership;
DROP TRIGGER IF EXISTS groups_no_cycle_trigger ON groups;
DROP FUNCTION IF EXISTS groups_no_cycle();
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS users;
