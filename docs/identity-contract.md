# WOU-ID identity contract

WOU-ID is the identity service for the World of Unreal projects. It owns
authentication, sessions, verified email, and provider links. Each game keeps
its own database and economy.

## Canonical account

`account_id` is the only account identifier returned to a game. It is stable
across login methods and projects.

Provider subjects are internal lookup values. WOU-ID maps Google, Play Games,
Apple, Discord, Facebook, CrazyGames, Poki, Steam, Epic, and wallet identities
to one account.

Email is a verified login method, not a replacement account key:

- OTP indexes the normalized email and returns its existing account.
- A social provider can link by email only when it reports the email as
  verified.
- An unverified or conflicting email never merges accounts automatically.
- A conflict returns an error instead of moving progress or overwriting a
  provider link.

## Service boundary

- WOU-ID stores identity and session data.
- SOW stores progression, matches, currencies, inventory, and purchase grants.
- WOU-ID's optional embedded wallets are identity-owned Web3 credentials;
  they are not a game's economy.
- The game receives `account_id` and keeps its own record under that key.

## OAuth callback contract

The provider consoles register these exact HTTPS callback URLs:

- `https://worldofunreal.com/auth/callback` for the central hub and other
  WOU-ID clients.
- `https://shadowsofwar.io/auth/callback` for the SOW direct callback.

The callback is chosen by the client before login and is pinned server-side.
The server stores the short-lived OAuth state, checks the provider and callback
match, consumes the state once, and requires S256 PKCE for X. Play Games is a
separate Android-native provider path; it does not use these web callbacks.

## Operator reset

`POST /api/v1/internal/profile/reset-test-data` is internal-only, bearer
protected, and dry-run by default. A real reset requires the exact text
`RESET_HUMAN_TEST_DATA`. It removes human test identity records while keeping
bots and global asset catalogs. Redb and Valkey APIs are used; database bytes
are never edited directly.

## Adding a provider

Implement verification in WOU-ID, store the provider subject in its identity
index, and return the existing `account_id`. Do not add provider-specific
account fields to a game.
