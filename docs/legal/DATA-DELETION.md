# wou-id — data deletion runbook (operator-only)

Player promises: Hyper `docs/legal/PRIVACY.md` (§5). This is the internal
procedure. Storage endpoints below are loopback-bound by design — never expose
them publicly.

## 0. Stores

- Hot cache: Valkey (OTP codes with TTL, rate limits, session hints).
- Durable: Redb (`wou_accounts.redb`) — canonical accounts + identity index.

## 1. Receive and verify (email path)

1. Request arrives at `privacy@worldofunreal.com` with the username and, if
   verified, from the linked email address.
2. Resolve the account ID first:
   `GET /api/v1/user/by-username/:username` on the operator host.
3. Confirm ownership: verified email match, OAuth external ID, wallet address,
   or creation date + recent activity. Display-name match alone is not enough.

## 2. Erase

For account `<id>`:

- Valkey: delete OTP/rate/session keys for the account and email
  (`DEL` by exact key; OTPs already carry a 10-minute TTL).
- Redb: remove the account row plus every identity-index mapping
  (`provider:external_id → id`), clan memberships, and follow-graph edges
  referencing the ID.
- Confirm session tokens can no longer validate (`GET /api/v1/auth/me`
  returns 401).

Deliberately retained (and disclosed): aggregate, non-identifiable records
with no account link.

## 3. Verify and reply

- Account lookup returns 404.
- Old token against `/api/v1/auth/me` returns 401.
- Reply with what was erased. Respond within 45 days; denials state the reason
  and offer appeal by reply.

## 4. Children under 13

Expedited: suspend first, erase second, reply to the parent/guardian.
