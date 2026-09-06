# WouID Security — Architecture, Controls & Operations

Public document. Contains **no secrets, no credentials, no PII**.
Thresholds below mirror `crates/wou-storage/src/store.rs` constants —
the code is the source of truth; this file explains intent and operations.

## Principles

1. **Secrets live only in the production env** (`/usr/local/etc/wou-id/wou-id.env`,
   `0600`). Missing secret = refused boot, never a fallback. Nothing secret is
   committed, ever.
2. **Reject cheap, send expensive.** Every intake check is an in-memory Valkey
   op (~0.1ms). SMTP delivery (seconds) only happens after all gates pass.
3. **No PII at rest beyond the account itself.** Valkey keys and logs carry
   12-hex tags (`wou_core::key_tag`), never raw emails.
4. **Silent enforcement.** Attackers observe 429/403/503; details go to logs
   and to the ops inbox, never to the requester.

## Threat model (what this stack defends)

- OTP bombing / mailer abuse for blacklist damage (per-email ladder, per-IP
  ceilings, global spike alert, nginx `limit_req` outer wall).
- Code guessing (5 failures burn the code; failures feed the same ladder).
- Challenge replay (web3 nonces are single-use and message-bound).
- Open-redirect token theft (OAuth `redirect_uri` pinned to hub + loopback).
- Upload path traversal (`media_type` is a closed enum; extensions whitelisted).
- Botnet floods (manual protection mode: intake paused, sessions alive).
- Supply chain (npm publishes only via OIDC Trusted Publisher + sigstore
  provenance from tag builds; no long-lived tokens).

## Controls inventory (code pointers)

| Control | Where |
|---|---|
| OTP ladder 3/15min → 24h → 90d ban + appeal | `wou-storage/src/store.rs::tally_otp_request` |
| Guess burn + abuse linkage | `store.rs::get_and_consume_otp` |
| IP throttle 100/h, 300/d (IPv6 → /64) | `store.rs::tally_ip`, `wou-server/src/routes/guard.rs::client_ip` |
| Protection mode flag | `store.rs::protection_mode`, gates in `otp.rs` + `anonymous.rs` |
| Spike counter | `store.rs::tally_global_minute`, alert in `otp.rs` |
| Plus-address normalization | `wou-core/src/models.rs::canonical_email` |
| OAuth pin / web3 nonce / upload enum | `routes/oauth.rs`, `routes/web3.rs`, `routes/upload.rs` |
| Welcome (once, verified email only) + admin alerts | `wou-mail/src/{mailer,templates}.rs` |
| Client cooldowns + `retry_after_seconds` | `@worldofunreal/id` (`describeOtpError`) + modals |
| nginx outer wall + HSTS | `deploy/id.worldofunreal.com.conf` (synced by `./wou` AND Actions deploy) |

## Operations runbook (read-only first)

Health:

```bash
sudo service wou_id status
curl -s https://id.worldofunreal.com/health
sudo nginx -t
```

Protection mode (Valkey DB 1, instant, no restart):

```bash
valkey-cli -n 1 SET wou_protect_mode 1   # ON: intake 503, sessions alive
valkey-cli -n 1 DEL wou_protect_mode     # OFF: restore immediately
valkey-cli -n 1 EXISTS wou_protect_mode  # status
```

Inspect abuse state (tags, never emails):

```bash
valkey-cli -n 1 KEYS "wou_otp_ban:*"
valkey-cli -n 1 TTL "wou_otp_penalty:<tag>"
valkey-cli -n 1 KEYS "wou_ip_block:*"
```

Lift a ban/penalty early (appeal granted):

```bash
valkey-cli -n 1 DEL "wou_otp_ban:<tag>" "wou_otp_penalty:<tag>"
```

Mailbox / admin rotation (backup first, official CLI only; Stalwart admin
auth lives server-side in `/root/STALWART_ADMIN.md` (0600) and the jail's
`rc.conf` — never in this repo):

```bash
ts=$(date +%s); sudo sqlite3 /zroot/jails/mail/var/db/stalwart/stalwart.db \
  ".backup /zroot/jails/mail/var/db/stalwart/backup_pre_action_${ts}.db"
# stcli query account  -> locate Id
# stcli update Account <id> --field 'credentials={"0":{"secret":"<new>","@type":"Password"}}'
# verify: JMAP https://mail.worldofunreal.com/jmap/session must return 200
```

Recovery admin rotation (brief mail downtime; edit `STALWART_RECOVERY_ADMIN`
in `/zroot/jails/mail/etc/rc.conf`, restart the service inside the jail, then
update all guide copies and keep them `0600`):

```bash
sudo jexec mail service stalwart restart
# verify OLD admin -> 401, NEW admin -> `stcli query domain` lists domains
```

Env rotation (additive edits only, then one restart; sessions reset on JWT change):

```bash
sudo awk -F= '/^WOU_(JWT_SECRET|SMTP_PASS)/{print $1, length($2)}' /usr/local/etc/wou-id/wou-id.env
sudo service wou_id restart && sleep 3 && sudo service wou_id status
```

Deploy (never manual binary swaps):

```bash
./wou deploy        # tests -> build -> install -> nginx sync -> restart -> health
```

`[WOU-ALERT]` catalog: `Email penalized 24h`, `Email banned`, `IP blocked`,
`OTP intake spike`. Alerts are best-effort and never fail auth.

## Secrets inventory (locations only — no values here, ever)

- `/usr/local/etc/wou-id/wou-id.env` (`0600`, owner `sowdb:sow`): JWT, 5 SMTP
  passwords, `WOU_ADMIN_ALERT_EMAIL`, OAuth clients, bot tokens. Template with
  placeholder names: `deploy/wou-id.env.template`.
- Mailbox passwords: Stalwart-side only, managed via `stalwart-cli`.
- GitHub Actions: `SSH_HOST`, `SSH_USER`, `SSH_PRIVATE_KEY` (repo secrets).
- npm publish: OIDC Trusted Publisher (no tokens anywhere).

## Incident log

- 2026-09-05: full SMTP+JWT rotation (5 mailboxes, env, restarts), verified
  SMTP-AUTH 5/5 + live OTP. Backup `backup_pre_action_1788596395.db`.
- 2026-09-05: transient SMTP `connection reset` bursts from host; service
  healthy via loopback and externally. Cause undetermined; watch item.
- 2026-09-05: `/etc/hosts` pins `mail.worldofunreal.com` → 127.0.0.1 on the
  host (avoids gateway hairpin for local SMTP).
- 2026-09-05: `security@worldofunreal.com` created (appeals + monitoring).
- 2026-09-05: Stalwart recovery admin rotated (rc.conf edit + service restart;
  old credential invalidated, verified 401/200; guide copies updated to 0600).
- 2026-09-05: Actions deploy now syncs `deploy/wou_id.rc.d` + nginx conf
  (sha256 parity verified repo↔remote; HSTS + `limit_req` live).

## For future agents (context without archaeology)

1. Read this file + `README.md` + `id/AGENTS_GUIDE.md`.
2. Live risk register and pre-authored decisions live **server-side only**:
   `/root/wou-ops/RISK-REGISTER.md` on ionos (0600, never in git).
3. Past sessions: `opencode session list` / `opencode export <id>`.
4. Rules that outlive sessions: `AGENTS.md` (pipeline law, containment
   protocol, zero-noise comms).
