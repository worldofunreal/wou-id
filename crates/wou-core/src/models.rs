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

    pub fn default_sender(&self) -> &'static str {
        match self {
            Self::ShadowsOfWar => "no-reply@shadowsofwar.io",
            Self::Cosmicrafts => "no-reply@cosmicrafts.com",
            Self::Nftropoly => "no-reply@nftropoly.com",
            Self::Darkrift => "no-reply@darkrift.ai",
            Self::WorldOfUnreal => "no-reply@worldofunreal.com",
        }
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
    /// Ethereum / EVM Wallet (EIP-4361 SIWE)
    Ethereum,
    /// Solana Wallet (SIWS)
    Solana,
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
            Self::Ethereum => "ethereum",
            Self::Solana => "solana",
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

/// A Linked External Identity associated with a PlayerAccount.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LinkedIdentity {
    pub provider: AuthProvider,
    pub external_id: String,
    pub linked_at: u64,
}

/// Generalized Player Profile metadata (compatible across games).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserProfile {
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub custom_attributes: HashMap<String, serde_json::Value>,
}

/// Master Player Account in World of Unreal Identity.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PlayerAccount {
    /// Canonical unique UUID.
    pub id: String,
    /// Public display name chosen by player.
    pub display_name: String,
    /// Primary verified email (if linked).
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the user has opted in to the marketing newsletter.
    #[serde(default)]
    pub newsletter_opt_in: bool,
    /// Account classification.
    #[serde(default)]
    pub kind: AccountKind,
    /// List of linked authentications.
    #[serde(default)]
    pub linked_identities: Vec<LinkedIdentity>,
    /// Profile metadata.
    #[serde(default)]
    pub profile: UserProfile,
    /// Creation timestamp (UTC epoch seconds).
    pub created_at: u64,
    /// Last update timestamp (UTC epoch seconds).
    pub updated_at: u64,
}

impl PlayerAccount {
    /// Creates a new anonymous account with zero friction.
    pub fn new_anonymous(id: String, display_name: Option<String>) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        let final_name = display_name.unwrap_or_else(|| {
            let short_id = if id.len() >= 4 { &id[..4] } else { &id };
            format!("Commander_{short_id}")
        });

        Self {
            id,
            display_name: final_name,
            email: None,
            newsletter_opt_in: false,
            kind: AccountKind::Human,
            linked_identities: Vec::new(),
            profile: UserProfile::default(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if account is anonymous (no verified email or linked identities).
    pub fn is_anonymous(&self) -> bool {
        self.email.is_none() && self.linked_identities.is_empty()
    }

    /// Check if a specific provider is already linked.
    pub fn has_provider(&self, provider: &AuthProvider) -> bool {
        self.linked_identities.iter().any(|li| &li.provider == provider)
    }

    /// Link a new identity to this account.
    pub fn link_identity(&mut self, provider: AuthProvider, external_id: String) {
        if !self.linked_identities.iter().any(|li| li.provider == provider && li.external_id == external_id) {
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
