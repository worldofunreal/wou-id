# wou-id — Privacy Notes (backend, pointer)

Canonical policy: <https://worldofunreal.com/privacy> (Controller: World of
Unreal · Contact: privacy@worldofunreal.com). It governs wou-id, Hyper, and
SDK consumers referencing it. Backend specifics below are covered by it.

## What id.worldofunreal.com stores

- Canonical account: ID, username, display name, email (if verified),
  newsletter flag, linked identities (provider + external ID), wallets,
  profile (avatar/banner/bio/country), clan tag, counters, timestamps.
- OTP: 6-digit code + email + context in Valkey with 10-minute TTL and
  per-address rate limits. Codes are single-use.
- Sessions: signed JWT (30 days). Server verifies signature; no session table.
- Logs: request logs for operation, security, and abuse prevention.

## What it never does

No sale of personal data. No advertising use. No card data. No passwords —
there is no password login to breach.

## Retention & deletion

Accounts persist until deleted per `DATA-DELETION.md`. OTPs expire in
10 minutes. Tokens expire in 30 days. See Hyper privacy for user rights.
