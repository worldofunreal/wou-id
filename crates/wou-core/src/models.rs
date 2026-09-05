use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Universal Game Context identifying the origin game or app within the World of Unreal ecosystem.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum GameContext {
    #[default]
    ShadowsOfWar,
    Cosmicrafts,
    Nftropoly,
    Darkrift,
    WorldOfUnreal,
}

impl GameContext {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ShadowsOfWar => "shadowsofwar",
            Self::Cosmicrafts => "cosmicrafts",
            Self::Nftropoly => "nftropoly",
            Self::Darkrift => "darkrift",
            Self::WorldOfUnreal => "worldofunreal",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ShadowsOfWar => "Shadows of War",
            Self::Cosmicrafts => "Cosmicrafts",
            Self::Nftropoly => "Nftropoly",
            Self::Darkrift => "Darkrift AI",
            Self::WorldOfUnreal => "World of Unreal",
        }
    }

    pub fn default_domain(&self) -> &'static str {
        match self {
            Self::ShadowsOfWar => "shadowsofwar.io",
            Self::Cosmicrafts => "cosmicrafts.com",
            Self::Nftropoly => "nftropoly.com",
            Self::Darkrift => "darkrift.ai",
            Self::WorldOfUnreal => "worldofunreal.com",
        }
    }

    /// Single sender for the whole org: one SDK, one mailbox.
    /// Per-game branding lives in the From name and template theme, not the address.
    pub fn default_sender(&self) -> &'static str {
        "no-reply@worldofunreal.com"
    }
}

/// Supported Authentication Providers for Linked Identities.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuthProvider {
    /// Verified Email via Stalwart OTP
    Email,
    /// CrazyGames portal SDK token
    CrazyGames,
    /// Poki game portal token
    Poki,
    /// Google Play Services / Google ID
    Google,
    /// Apple Game Center / Apple ID
    Apple,
    /// Discord User Account OAuth2
    Discord,
    /// X / Twitter Account OAuth2
    Twitter,
    /// Meta / Facebook Account OAuth2
    Meta,
    /// Ethereum / EVM Wallet (EIP-4361 SIWE)
    Ethereum,
    /// Solana Wallet (SIWS)
    Solana,
    /// Internet Identity / ICP Principal (id.ai)
    InternetIdentity,
    /// Custom third-party affiliate portal
    Custom(String),
}

impl AuthProvider {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Email => "email",
            Self::CrazyGames => "crazygames",
            Self::Poki => "poki",
            Self::Google => "google",
            Self::Apple => "apple",
            Self::Discord => "discord",
            Self::Twitter => "twitter",
            Self::Meta => "meta",
            Self::Ethereum => "ethereum",
            Self::Solana => "solana",
            Self::InternetIdentity => "internet_identity",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Distinguishes Human players from Bot accounts and Fillers.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    #[default]
    Human,
    Bot,
}

/// Deterministic Embedded Multi-Chain Wallet Vault for seamless Web2/Web3 onboarding.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct EmbeddedWallets {
    #[serde(default)]
    pub evm_address: String,
    #[serde(default)]
    pub solana_address: String,
    #[serde(default)]
    pub icp_principal: String,
    #[serde(default)]
    pub bitcoin_address: String,
}

/// Cross-Game Studio Stats across Shadows of War, Cosmicrafts, and Nftropoly.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct CrossGameProfile {
    // Shadows of War (RTS)
    #[serde(default)]
    pub sow_rank: String,
    #[serde(default)]
    pub sow_elo: u32,
    #[serde(default)]
    pub sow_matches: u32,
    #[serde(default)]
    pub sow_wins: u32,
    #[serde(default)]
    pub sow_faction: String,
    // Cosmicrafts (Space Strategy)
    #[serde(default)]
    pub cosmicrafts_level: u32,
    #[serde(default)]
    pub cosmicrafts_fleet_power: u32,
    // Nftropoly (Real Estate Metaverse)
    #[serde(default)]
    pub nftropoly_net_worth: u64,
    #[serde(default)]
    pub nftropoly_titles: u32,
}

/// A social activity timeline event emitted across the studio ecosystem.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SocialActivity {
    pub id: String,
    pub account_id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub activity_type: String, // "sow_victory", "level_up", "clan_join", "badge_unlocked"
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub game: GameContext,
    #[serde(default)]
    pub timestamp: u64,
}

/// A Linked External Identity associated with a PlayerAccount.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LinkedIdentity {
    pub provider: AuthProvider,
    pub external_id: String,
    #[serde(default)]
    pub linked_at: u64,
}

/// Generalized Player Profile metadata (compatible across games).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserProfile {
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub banner_url: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub is_verified: bool,
    #[serde(default)]
    pub custom_attributes: HashMap<String, serde_json::Value>,
}

/// Master Player Account in World of Unreal Identity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PlayerAccount {
    /// Canonical unique UUID.
    pub id: String,
    /// Unique public handle (@handle, e.g. "bizkit" or "commander_4821").
    #[serde(default)]
    pub username: String,
    /// Public display name chosen by player (e.g. "BiZKiT" or "Commander 4821").
    #[serde(default)]
    pub display_name: String,
    /// Primary verified email (if linked).
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the user has opted in to the marketing newsletter.
    #[serde(default)]
    pub newsletter_opt_in: bool,
    /// Whether the one-time welcome email was already sent (idempotency).
    #[serde(default)]
    pub welcome_sent: bool,
    /// Account classification.
    #[serde(default)]
    pub kind: AccountKind,
    /// Auto-provisioned zero-overhead embedded wallets (EVM, SOL, ICP, BTC).
    #[serde(default)]
    pub embedded_wallets: EmbeddedWallets,
    /// Unified cross-game studio statistics.
    #[serde(default)]
    pub game_stats: CrossGameProfile,
    /// Social graph follower counts.
    #[serde(default)]
    pub followers_count: u32,
    #[serde(default)]
    pub following_count: u32,
    /// Clan affiliation (if member of a guild).
    #[serde(default)]
    pub clan_tag: Option<String>,
    #[serde(default)]
    pub clan_name: Option<String>,
    /// List of linked authentications.
    #[serde(default)]
    pub linked_identities: Vec<LinkedIdentity>,
    /// Profile metadata.
    #[serde(default)]
    pub profile: UserProfile,
    /// Creation timestamp (UTC epoch seconds).
    #[serde(default)]
    pub created_at: u64,
    /// Last update timestamp (UTC epoch seconds).
    #[serde(default)]
    pub updated_at: u64,
}

/// Curated noble animals with pleasant psychological connotations and noble spirit.
pub const NOBLE_ANIMALS: &[(&str, &str, &str)] = &[
    ("falcon", "🦅", "from-sky-500 to-indigo-900"),
    ("panther", "🐆", "from-purple-700 to-slate-950"),
    ("wolf", "🐺", "from-slate-600 to-cyan-700"),
    ("lynx", "🐱", "from-amber-600 to-amber-950"),
    ("phoenix", "🔥", "from-red-600 to-orange-600"),
    ("dragon", "🐉", "from-emerald-600 to-teal-950"),
    ("tiger", "🐯", "from-amber-500 to-orange-900"),
    ("eagle", "🦅", "from-yellow-600 to-stone-900"),
    ("raven", "🦅", "from-purple-900 to-slate-950"),
    ("otter", "🦦", "from-teal-600 to-cyan-900"),
    ("fox", "🦊", "from-orange-600 to-rose-900"),
    ("jaguar", "🐆", "from-yellow-500 to-amber-950"),
    ("hawk", "🦅", "from-amber-700 to-stone-900"),
    ("bear", "🐻", "from-amber-900 to-emerald-950"),
    ("cheetah", "🐆", "from-yellow-400 to-amber-800"),
    ("owl", "🦉", "from-indigo-600 to-slate-950"),
    ("orca", "🐋", "from-blue-600 to-slate-950"),
    ("bison", "🦬", "from-amber-800 to-stone-950"),
];

/// Generates a noble animal identity (@animal_###, e.g. @falcon_382) with emoji avatar.
pub fn generate_noble_animal_identity(account_id: &str, display_name: Option<String>) -> (String, String, UserProfile) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&account_id, &mut hasher);
    let hash_val = std::hash::Hasher::finish(&hasher);

    let animal_idx = (hash_val as usize) % NOBLE_ANIMALS.len();
    let (animal_name, emoji, theme) = NOBLE_ANIMALS[animal_idx];

    // 3-digit suffix (100..=999)
    let num = 100 + ((hash_val / NOBLE_ANIMALS.len() as u64) % 900) as u32;

    let username = format!("{animal_name}{num}");
    let final_display_name = display_name.unwrap_or_else(|| {
        let mut chars = animal_name.chars();
        let cap_animal = match chars.next() {
            None => String::new(),
            Some(f) => f.to_uppercase().collect::<String>() + chars.as_str(),
        };
        format!("{cap_animal} {num}")
    });

    let mut custom = std::collections::HashMap::new();
    custom.insert("animal_emoji".into(), serde_json::Value::String(emoji.into()));
    custom.insert("animal_theme".into(), serde_json::Value::String(theme.into()));

    let profile = UserProfile {
        avatar_url: None,
        banner_url: None,
        country: None,
        bio: Some(format!("Player · {}", emoji)),
        is_verified: false,
        custom_attributes: custom,
    };

    (username, final_display_name, profile)
}

impl PlayerAccount {
    /// Creates a new account with deterministic embedded wallets and clean noble handle.
    pub fn new_with_wallets(
        id: String,
        username: Option<String>,
        display_name: Option<String>,
        wallets: EmbeddedWallets,
    ) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        let (gen_user, gen_name, gen_profile) = generate_noble_animal_identity(&id, display_name);
        let final_user = username.unwrap_or(gen_user);

        Self {
            id,
            username: final_user,
            display_name: gen_name,
            email: None,
            newsletter_opt_in: false,
            welcome_sent: false,
            kind: AccountKind::Human,
            embedded_wallets: wallets,
            game_stats: CrossGameProfile {
                sow_rank: "Bronze I".into(),
                sow_elo: 1000,
                sow_matches: 0,
                sow_wins: 0,
                sow_faction: "Solar Dominion".into(),
                cosmicrafts_level: 1,
                cosmicrafts_fleet_power: 100,
                nftropoly_net_worth: 50000,
                nftropoly_titles: 0,
            },
            followers_count: 0,
            following_count: 0,
            clan_tag: None,
            clan_name: None,
            linked_identities: Vec::new(),
            profile: gen_profile,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if a specific provider is already linked.
    pub fn has_provider(&self, provider: &AuthProvider) -> bool {
        self.linked_identities.iter().any(|li| &li.provider == provider)
    }

    /// Links an external identity provider to this player.
    pub fn link_identity(&mut self, provider: AuthProvider, external_id: String) {
        if !self.linked_identities.iter().any(|i| i.provider == provider && i.external_id == external_id) {
            let now = chrono::Utc::now().timestamp() as u64;
            self.linked_identities.push(LinkedIdentity {
                provider,
                external_id,
                linked_at: now,
            });
            self.updated_at = now;
        }
    }
}

/// Active User Session Claims.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionClaims {
    /// Subject (Account ID).
    pub sub: String,
    /// Display name.
    pub name: String,
    /// Email (if verified).
    pub email: Option<String>,
    /// Game context where session originated.
    pub context: GameContext,
    /// Issued at timestamp.
    pub iat: u64,
    /// Expiration timestamp.
    pub exp: u64,
}

/// OTP State record stored in Valkey/Redis during verification window.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingOtp {
    pub code: String,
    pub account_id: Option<String>,
    pub email: String,
    pub context: GameContext,
    pub newsletter_opt_in: bool,
    pub requested_at: u64,
}

/// QR login challenge (Valkey-only, 5-minute TTL, single-use).
/// Only the secret hash is stored. The issued session token lives in the
/// challenge only during the 60s delivery window, then the key is consumed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QrChallenge {
    pub id: String,
    pub secret_hash: String,
    pub context: GameContext,
    pub created_at: u64,
    pub approved_account_id: Option<String>,
    pub session_token: Option<String>,
}

/// Authoritative Clan entity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Clan {
    /// 2-5 uppercase characters identifier (e.g. "SOW", "VOID", "UNREAL")
    pub tag: String,
    /// Human-readable clan name (3-32 characters)
    pub name: String,
    /// Public description / motto
    pub description: String,
    /// Creator and leader account ID
    pub leader_id: String,
    /// Creator and leader username handle
    pub leader_username: String,
    /// Optional clan avatar / emblem URL
    pub avatar_url: Option<String>,
    /// Optional clan banner URL
    pub banner_url: Option<String>,
    /// Total member count
    pub member_count: u32,
    /// Clan creation timestamp
    pub created_at: u64,
}

/// Role of a player within a Clan.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClanRole {
    Leader,
    Officer,
    Member,
}

/// Member record in a Clan roster.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClanMember {
    pub account_id: String,
    pub username: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub animal_emoji: Option<String>,
    pub role: ClanRole,
    pub joined_at: u64,
}

/// Fast search result for player discovery.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PlayerSearchResult {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub animal_emoji: Option<String>,
    pub clan_tag: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_player_account_deserialization() {
        let legacy_json = r#"{
            "id": "52948534-1c9f-4def-bc8e-80390d3287a6",
            "display_name": "Commander BiZKiT",
            "email": "bizkit@example.com",
            "newsletter_opt_in": true,
            "kind": "human",
            "linked_identities": [
                {
                    "provider": "google",
                    "external_id": "104928374928174",
                    "linked_at": 1787300000
                }
            ],
            "profile": {
                "avatar_url": "https://lh3.googleusercontent.com/a/mock",
                "banner_url": null,
                "country": null,
                "bio": null,
                "is_verified": true,
                "custom_attributes": {}
            },
            "created_at": 1787300000,
            "updated_at": 1787300000
        }"#;

        let account: PlayerAccount = serde_json::from_str(legacy_json).expect("Should cleanly deserialize legacy accounts");
        assert_eq!(account.id, "52948534-1c9f-4def-bc8e-80390d3287a6");
        assert_eq!(account.display_name, "Commander BiZKiT");
        assert_eq!(account.username, "");
        assert_eq!(account.followers_count, 0);
        assert_eq!(account.following_count, 0);
        assert_eq!(account.embedded_wallets.evm_address, "");
    }

    #[test]
    fn test_noble_animal_identity_format() {
        let (username, _display_name, profile) = generate_noble_animal_identity("test_account_uuid_12345", None);
        assert!(!username.contains('_'), "Username should not contain an underscore: {}", username);
        
        let valid_animals: Vec<&str> = NOBLE_ANIMALS.iter().map(|(a, _, _)| *a).collect();
        let matched = valid_animals.iter().any(|animal| username.starts_with(animal));
        assert!(matched, "Username {} must start with a valid noble animal", username);
        
        let digits: String = username.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits.len(), 3, "Username must end with 3 digits: {}", username);
        let num: u32 = digits.parse().expect("3 digits suffix must parse");
        assert!(num >= 100 && num <= 999, "Number must be between 100 and 999: {}", num);
        
        assert!(profile.custom_attributes.contains_key("animal_emoji"));
        assert!(profile.custom_attributes.contains_key("animal_theme"));
    }
}
