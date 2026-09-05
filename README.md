# 🛡️ World of Unreal Identity (`wou-id`)

![WouID](./docs/assets/wouid.svg)

> **WouID — Universal, Anonymous-First, Progressive Authentication & Multi-Platform Identity Engine for World of Unreal Games & Ecosystem Products.**

[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Stalwart Mail Engine](https://img.shields.io/badge/email-Stalwart%20v0.16%20TLS-emerald.svg)](https://stalw.art)

---

## 🌟 Vision & Key Highlights

* **Anonymous-First & Zero Friction:** Players enter the game immediately as guests with canonical bearer IDs in `localStorage`. Zero login walls on first play.
* **Progressive OTP Registration:** When players want to save progress, claim rewards, or sync cross-platform, they link their email via a high-speed **6-digit OTP code** dispatched directly through your own **Stalwart Mail Server**.
* **Double Opt-In & Compliance:** 100% compliant with Gmail, Yahoo, and Microsoft bulk sender requirements (DKIM RSA-2048 + Ed25519, SPF `-all`, DMARC `p=reject`, MTA-STS, and 1-Click RFC 8058 Unsubscribe).
* **Multi-Provider Identity Linking:** A single `PlayerAccount` seamlessly bridges:
  * 📧 **Verified Email** (Stalwart OTP)
  * 🎮 **Web Portals** (CrazyGames, Poki, GameDistribution)
  * 📱 **Mobile** (Google Play Services, Apple Game Center)
  * 🌐 **Web3 Wallets** (Ethereum EIP-4361 SIWE, Solana SIWS) without slow blockchain canisters.
* **High Performance Stack:** Built in **pure Rust**, utilizing **Valkey** for hot session caches and **Redb** for ultra-fast, zero-overhead durable embedded storage.

---

## 🏗️ Architecture & State Machine

```mermaid
stateDiagram-v2
    [*] --> Anonymous_Player: Player boots game (Zero friction)
    
    state Anonymous_Player {
        [*] --> GuestSession: UUID assigned in localStorage
        GuestSession --> Active_Gameplay: Plays matches, earns XP & gold
    }
    
    Anonymous_Player --> OTP_Flow: Clicks 'Save Progress / Claim Rewards'
    
    state OTP_Flow {
        OTP_Flow --> Code_Generated: Backend generates 6-digit OTP in Valkey (TTL 10m)
        Code_Generated --> Stalwart_Dispatch: Stalwart delivers branded HTML email in < 2s
        Stalwart_Dispatch --> Code_Entered: Player types 6 digits in modal
    }
    
    Code_Entered --> Permanent_Account: OTP Validated
    Code_Entered --> OTP_Flow: Invalid code / Retry
    
    state Permanent_Account {
        Permanent_Account --> Email_Linked: Account promoted to permanent
        Email_Linked --> Newsletter_OptIn: Auto-subscribed to game newsletter
        Email_Linked --> Rewards_Granted: Unlocks rewards & badge
    }
    
    Permanent_Account --> Cross_Platform_Link: Link Additional Platforms
    state Cross_Platform_Link {
        [*] --> CrazyGames: Token SDK verified
        [*] --> Mobile: Apple / Google token verified
        [*] --> Web3: EVM / Solana SIWE signature verified
    }
```

---

## 📦 Workspace Crates

| Crate | Purpose |
| :--- | :--- |
| **[`wou-core`](crates/wou-core)** | Core domain models (`PlayerAccount`, `LinkedIdentity`, `AuthProvider`, `UserProfile`, `SessionClaims`). |
| **[`wou-mail`](crates/wou-mail)** | Stalwart SMTP transport engine with responsive, branded HTML templates for each game domain. |
| **[`wou-crypto`](crates/wou-crypto)** | Cryptographic tools: Secure 6-digit OTP generation, JWT token manager, SIWE (EVM), SIWS (Solana), CrazyGames verifier. |
| **[`wou-storage`](crates/wou-storage)** | Storage backend: Hot Valkey cache (rate limits, OTPs) + Durable Redb player table with inverted identity indexes. |
| **[`wou-server`](crates/wou-server)** | Axum REST API server, CORS handlers, route controllers, and health endpoints. |
| **[`wou-client`](crates/wou-client)** | Universal Rust Client SDK compiling to both native and `wasm32-unknown-unknown`. |
| **[`@worldofunreal/id`](id)** | Single TypeScript package: auth client + official sign-in modal for every frontend. |

---

## 🚀 REST API Reference

### 1. Anonymous Authentication
```http
POST /api/v1/auth/anonymous
Content-Type: application/json

{
  "account_id": "optional-stored-uuid",
  "display_name": "Commander_Alpha",
  "context": "shadowsofwar"
}
```

### 2. Request OTP Verification Code
```http
POST /api/v1/auth/otp/request
Content-Type: application/json

{
  "email": "player@gmail.com",
  "account_id": "current-anon-uuid",
  "context": "shadowsofwar",
  "newsletter_opt_in": true
}
```

### 3. Verify OTP & Promote Account
```http
POST /api/v1/auth/otp/verify
Content-Type: application/json

{
  "email": "player@gmail.com",
  "code": "849201",
  "account_id": "current-anon-uuid",
  "context": "shadowsofwar"
}
```

### 4. Link External Provider (CrazyGames / Web3)
```http
POST /api/v1/auth/link/crazygames
POST /api/v1/auth/link/ethereum
POST /api/v1/auth/link/solana
```

### 5. Newsletter 1-Click Management (RFC 8058)
```http
POST /api/v1/newsletter/subscribe
POST /api/v1/newsletter/unsubscribe
```

---

## 💻 Quickstart (TypeScript / JavaScript SDK)

```typescript
import { WouIdClient } from '@worldofunreal/id';

const auth = new WouIdClient({ baseUrl: 'https://id.worldofunreal.com' });

// 1. Boot game immediately as anonymous
const { account, session_token } = await auth.startAnonymous('shadowsofwar');
console.log('Logged in as:', account.display_name);

// 2. When player wants to save progress:
await auth.requestOtp('player@gmail.com', 'shadowsofwar');

// 3. User submits 6-digit code:
const verified = await auth.verifyOtp('player@gmail.com', '849201', 'shadowsofwar');
console.log('Account saved & linked to:', verified.account.email);
```

---

## 💻 Quickstart (Rust WASM Client)

```rust
use wou_client::{WouClient, GameContext};

let client = WouClient::new("https://id.worldofunreal.com");

// Step 0: Start anonymous session
let (account, token) = client.start_or_restore_anonymous(
    stored_id,
    Some("Commander".into()),
    GameContext::ShadowsOfWar
).await?;

// Step 1: Request OTP
client.request_otp("player@gmail.com", Some(account.id), GameContext::ShadowsOfWar, true).await?;

// Step 2: Verify OTP
let result = client.verify_otp("player@gmail.com", "849201", Some(account.id), GameContext::ShadowsOfWar).await?;
```

---

## 🛠️ Build & Test

```bash
# Check all workspace crates
cargo check --workspace

# Run all unit and integration tests
cargo test --workspace

# Build production binary
cargo build --release --bin wou-server
```

---

## 📜 License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
