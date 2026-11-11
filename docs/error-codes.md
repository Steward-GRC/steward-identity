# Error codes

Every coded gRPC error from the identity service carries an `ErrorInfo` with the symbol as
its reason, the domain `identity` and the code in `codeNum`. Only user-safe messages reach the
caller; every other code is sent as `Code N: Internal Error`.

| Code | Symbol | Area | Cause | User-safe |
| --- | --- | --- | --- | --- |
| 5000 | `INTERNAL` | identity | an uncoded failure inside the identity service | no |
| 5001 | `SSO_PROVIDER_UNREACHABLE` | SSO connection | the SSO broker's admin API refused or didn't answer while a connection was set up; the org metadata names the organisation | yes |
| 5002 | `ADMIN_AUTHZ_REQUIRED` | admin access | an admin call came from neither a site-admin nor the admin CLI | yes |
| 5003 | `ROOT_REQUIRED` | root-only grant | a non-root admin tried a root-only grant or a change to the root admins | yes |
| 5004 | `SSO_JIT_DISABLED` | SSO sign-in | a first-seen SSO user signed in through a connection that doesn't create accounts | yes |
| 5005 | `SESSIONS_UNAVAILABLE` | list sessions | the sign-in service's session API isn't configured or didn't answer | yes |
| 5006 | `SESSION_REVOKE_UNAVAILABLE` | revoke sessions | the sign-in service's session API isn't configured or didn't answer, so nothing was revoked | yes |
| 5007 | `LOCAL_ACCOUNTS_UNAVAILABLE` | local accounts | the sign-in service's admin API isn't configured, so local accounts and passwords can't be managed | yes |
| 5008 | `USER_HAS_PENDING_APPROVALS` | delete user | the account still holds pending approval seats, which a delete would strand | yes |
| 5009 | `USER_DELETE_CHECKS_UNAVAILABLE` | delete user | a mandatory delete or delete-preview step couldn't run; the step metadata names it | yes |
| 5010 | `ACT_AS_FORBIDDEN` | act-as | an admin acting as another user tried a password, second-factor, delete, role or permission change | yes |
| 5011 | `CURRENT_PASSWORD_WRONG` | change password | the current password given with a password change did not match the account's password | yes |
| 5012 | `PASSWORD_TOO_WEAK` | change password | the sign-in service's password policy refused the new password | yes |
| 5013 | `NO_LOCAL_PASSWORD` | change password | the account signs in through an identity provider and has no local password to change | yes |
| 5014 | `PASSWORD_CHANGE_UNAVAILABLE` | change password | the sign-in service's public or admin API isn't configured or didn't answer, so the password was not changed | yes |
