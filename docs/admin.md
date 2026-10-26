# Admin console

The admin console is a web UI for operators at /admin. It needs an
authenticated web session whose user has the admin flag. Every state
change is a POST guarded by CSRF, and destructive actions such as
password replacement and user deletion ask for the admin's own password
again (step-up confirmation).

## Overview

/admin shows stat tiles (users, active today and seven days, storage
used, snapshots, active tokens, sessions, pending approvals, banned
users, locked usernames, IP blocks), a live 60 minute request ring, 30
day charts (requests, errors, signups, logins, snapshots, bytes, user
and storage growth), top users and apps, the 15 newest audit events and
a security checkup summary. Chart data resets on restart except the
daily rows that the analytics collector flushes to stats_daily.

## Users

/admin/users lists accounts with search, state filter, sort and paging.
The user page shows tier, quota, usage, tokens, sessions and actions:
ban (optional expiry), unban, approve or reject pending accounts, unlock
a rate limited username, set or generate a password, grant or revoke
admin, disable, enable, delete. A generated password is shown once and
forces a change at the next login.

## Access

/admin/access manages invites (create returns the plain code once, only
its hash is stored) and the IP blocklist (CIDR or single address, optional
expiry, refuses to cover your own address or a trusted proxy).

## Settings

/admin/settings edits runtime tunables stored as database overrides on
top of the config file. Persisted overrides win over file values and
survive restarts; SIGHUP re-reads the file and only changes the defaults.
Keys: site.name, site.description, site.terms_url, site.privacy_url,
site.contact, site.announcement_text, site.announcement_level,
site.show_ban_reason, registration.mode, registration.per_sec,
registration.require_approval, registration.max_per_ip_per_day,
quota.default_tier, quota.tiers, maintenance.enabled,
maintenance.message, token.default_ttl, token.max_ttl,
token.max_per_user, web.login_per_min, web.session_idle,
web.session_absolute, auth.failed_auth_per_sec.

## Audit

/admin/audit is the instance-wide event log (filterable by action, actor,
target and time, cursor paging, CSV export). Settings changes, moderation
actions and logins are recorded with ip and request id but never
credentials.

## Security

/admin/security groups checkup findings by severity, each with a fix
hint and a stable anchor. Rules cover TLS, cookie security, open
registration without limits, admin accounts without TOTP, secret length,
sandbox off, CORS, ops listener exposure, anonymous auth, missing
trusted proxies, unlimited default tier and stale backups.

## System

/admin/system shows build and runtime info, database and blob sizes,
free space and the last GC report, plus POST actions: run GC, run fsck
(single flight, background) and back up the SQLite metadata with
VACUUM INTO when admin.backup_dir is set (keeps the newest 7 files).

## Public instance checklist

TLS via the built in listener or a proxy, public_url set to the https
address, registration invite only or open with require_approval, quotas
and bandwidth limits enabled, trusted proxies configured, admin
accounts on TOTP, terms and privacy links set, admin.backup_dir
configured and backed up.
