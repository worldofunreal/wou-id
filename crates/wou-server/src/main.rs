mod auth;
mod bots;
mod routes;
mod state;

pub use auth::AuthSession;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wou_crypto::{JwtManager, OAuthManager};
use wou_mail::{StalwartMailer, StalwartMailerConfig};
use wou_storage::WouStorage;

use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Tracing Logger
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wou_server=debug,wou_storage=debug,wou_mail=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting World of Unreal Identity Server (WOU-ID)...");

    // 2. Load Configuration from Environment
    let host = std::env::var("WOU_HOST").unwrap_or_else(|_| "0.0.0.0".into());
    let port: u16 = std::env::var("WOU_PORT")
        .unwrap_or_else(|_| "25570".into())
        .parse()
        .expect("WOU_PORT must be a valid u16 integer");

    let redis_url = std::env::var("WOU_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".into());
    let redb_path = std::env::var("WOU_REDB_PATH").unwrap_or_else(|_| "/tmp/wou_accounts.redb".into());

    // Required secrets: no fallbacks. Missing env = refuse to boot (open-source safe).
    let jwt_secret =
        std::env::var("WOU_JWT_SECRET").expect("FATAL: WOU_JWT_SECRET must be set in environment");

    let smtp_host = std::env::var("WOU_SMTP_HOST").unwrap_or_else(|_| "mail.worldofunreal.com".into());
    let smtp_port: u16 = std::env::var("WOU_SMTP_PORT")
        .unwrap_or_else(|_| "465".into())
        .parse()
        .unwrap_or(465);

    let mut domain_passwords = std::collections::HashMap::new();
    domain_passwords.insert(
        "no-reply@worldofunreal.com".to_string(),
        std::env::var("WOU_SMTP_PASS_WORLDOFUNREAL")
            .expect("FATAL: WOU_SMTP_PASS_WORLDOFUNREAL must be set in environment"),
    );
    domain_passwords.insert(
        "no-reply@shadowsofwar.io".to_string(),
        std::env::var("WOU_SMTP_PASS_SHADOWSOFWAR")
            .expect("FATAL: WOU_SMTP_PASS_SHADOWSOFWAR must be set in environment"),
    );
    domain_passwords.insert(
        "no-reply@cosmicrafts.com".to_string(),
        std::env::var("WOU_SMTP_PASS_COSMICRAFTS")
            .expect("FATAL: WOU_SMTP_PASS_COSMICRAFTS must be set in environment"),
    );
    domain_passwords.insert(
        "no-reply@darkrift.ai".to_string(),
        std::env::var("WOU_SMTP_PASS_DARKRIFT")
            .expect("FATAL: WOU_SMTP_PASS_DARKRIFT must be set in environment"),
    );
    domain_passwords.insert(
        "no-reply@nftropoly.com".to_string(),
        std::env::var("WOU_SMTP_PASS_NFTROPOLY")
            .expect("FATAL: WOU_SMTP_PASS_NFTROPOLY must be set in environment"),
    );

    let otp_expiry_seconds: u64 = std::env::var("WOU_OTP_EXPIRY_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse()
        .unwrap_or(600);

    // Optional ops inbox for abuse alerts (unset = log-only, never fail boot).
    let admin_alert_email = std::env::var("WOU_ADMIN_ALERT_EMAIL")
        .ok()
        .filter(|s| !s.trim().is_empty());

    // Closed producer set for asset mint/freeze/restore (unset = fail closed).
    let producer_ids: Vec<String> = std::env::var("WOU_PRODUCER_IDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // 3. Initialize Storage, Stalwart Mailer, and OAuth Manager
    let storage = WouStorage::new(&redis_url, &redb_path)?;
    let mailer_config = StalwartMailerConfig {
        smtp_host,
        smtp_port,
        domain_passwords,
    };
    let mailer = StalwartMailer::new(mailer_config)?;
    let jwt = Arc::new(JwtManager::new(&jwt_secret));
    let oauth = Arc::new(OAuthManager::new());
    let bots = Arc::new(bots::BotClients::new());
    // Never block boot on Discord: register in the background, best-effort.
    tokio::spawn({
        let bots = bots.clone();
        async move { bots.discord_register_commands().await }
    });

    let state = AppState {
        storage,
        mailer,
        jwt,
        oauth,
        bots,
        otp_expiry_seconds,
        admin_alert_email,
        producer_ids,
    };

    // 4. Configure CORS & Routes
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Health Check
        .route("/health", get(|| async { "WOU-ID Online 200 OK" }))
        // Anonymous-First Auth (games use it; Hyper login-wall does not)
        .route("/api/v1/auth/anonymous", post(routes::anonymous::handle_anonymous))
        // Session (Hyper boot validation + remember-me)
        .route("/api/v1/auth/me", get(routes::session::handle_me))
        .route("/api/v1/auth/refresh", post(routes::session::handle_refresh))
        .route("/api/v1/auth/logout", post(routes::session::handle_logout))
        // Bot links + webhooks (push approval)
        .route("/api/v1/bots/link/start", post(routes::bots::handle_link_start))
        .route("/api/v1/bots/linked", get(routes::bots::handle_linked))
        .route("/api/v1/bots/link/:ns", post(routes::bots::handle_unlink))
        .route("/api/v1/bots/telegram", post(routes::bots::handle_telegram_webhook))
        .route("/api/v1/bots/discord", post(routes::bots::handle_discord_interactions))
        // QR login (desktop shows code, authed phone approves)
        .route("/api/v1/auth/qr/start", post(routes::qr::handle_qr_start))
        .route("/api/v1/auth/qr/:id/status", post(routes::qr::handle_qr_status))
        .route("/api/v1/auth/qr/:id/approve", post(routes::qr::handle_qr_approve))
        .route("/api/v1/auth/qr/:id/cancel", post(routes::qr::handle_qr_cancel))
        // Stalwart OTP Registration & Verification
        .route("/api/v1/auth/otp/request", post(routes::otp::handle_request_otp))
        .route("/api/v1/auth/otp/send", post(routes::otp::handle_request_otp))
        .route("/api/v1/auth/otp/verify", post(routes::otp::handle_verify_otp))
        // OAuth2 Auth
        .route("/api/v1/auth/oauth/login/:provider", get(routes::oauth::handle_oauth_login))
        .route("/api/v1/auth/oauth/callback/:provider", post(routes::oauth::handle_oauth_callback))
        // Web3 Direct Authentication (Solana & EVM)
        .route("/api/v1/auth/web3/challenge", post(routes::web3::handle_web3_challenge))
        .route("/api/v1/auth/web3/verify", post(routes::web3::handle_web3_verify))
        // External Portal & Web3 Linking
        .route("/api/v1/auth/link/crazygames", post(routes::link::handle_link_crazygames))
        .route("/api/v1/auth/link/ethereum", post(routes::link::handle_link_ethereum))
        .route("/api/v1/auth/link/solana", post(routes::link::handle_link_solana))
        // Profile & Username Handle Management
        .route("/api/v1/user/profile/:id", get(routes::profile::handle_get_profile).put(routes::profile::handle_update_profile))
        .route("/api/v1/user/by-username/:username", get(routes::profile::handle_get_by_username))
        .route("/api/v1/user/check-username/:username", get(routes::profile::handle_check_username))
        .route("/api/v1/user/search", get(routes::profile::handle_search_players))
        .route("/api/v1/user/upload-media", post(routes::upload::handle_upload_media))
        // Clans & Guilds
        .route("/api/v1/clans/create", post(routes::clan::handle_create_clan))
        .route("/api/v1/clans/list", get(routes::clan::handle_list_clans))
        .route("/api/v1/clans/:tag", get(routes::clan::handle_get_clan))
        .route("/api/v1/clans/:tag/join", post(routes::clan::handle_join_clan))
        .route("/api/v1/clans/:tag/leave", post(routes::clan::handle_leave_clan))
        // Social Graph & Cross-Activity Stream
        .route("/api/v1/social/follow/:target_id", post(routes::social::handle_follow_user))
        .route("/api/v1/social/unfollow/:target_id", post(routes::social::handle_unfollow_user))
        .route("/api/v1/social/graph/:account_id", get(routes::social::handle_get_social_graph))
        .route("/api/v1/social/feed", get(routes::social::handle_get_global_feed))
        .route("/api/v1/social/activity", post(routes::social::handle_record_activity))
        // Inventory — tradable collectibles (authoritative, Redb)
        .route("/api/v1/inventory/me", get(routes::inventory::handle_get_my_inventory))
        .route("/api/v1/inventory/collect", post(routes::inventory::handle_collect))
        .route("/api/v1/inventory/:id", get(routes::inventory::handle_get_inventory))
        .route("/api/v1/inventory/trade", post(routes::inventory::handle_trade_create))
        .route("/api/v1/inventory/trades", get(routes::inventory::handle_trade_list))
        .route("/api/v1/inventory/trade/:id", get(routes::inventory::handle_trade_get))
        .route("/api/v1/inventory/trade/:id/accept", post(routes::inventory::handle_trade_accept))
        .route("/api/v1/inventory/trade/:id/cancel", post(routes::inventory::handle_trade_cancel))
        // Digital assets — custodial collectibles (registry + instances + events)
        .route("/api/v1/assets/collections", post(routes::assets::handle_create_collection).get(routes::assets::handle_list_collections))
        .route("/api/v1/assets/collections/:id/tokens", get(routes::assets::handle_collection_tokens))
        .route("/api/v1/assets/claim", post(routes::assets::handle_claim))
        .route("/api/v1/assets/transfer/:id", post(routes::assets::handle_transfer))
        .route("/api/v1/assets/freeze/:id", post(routes::assets::handle_freeze))
        .route("/api/v1/assets/restore/:id", post(routes::assets::handle_restore))
        .route("/api/v1/assets/:id", get(routes::assets::handle_get_asset))
        .route("/api/v1/assets/owner/:account", get(routes::assets::handle_owner_assets))
        .route("/api/v1/assets/:id/events", get(routes::assets::handle_asset_events))
        // Newsletter Management
        .route("/api/v1/newsletter/subscribe", post(routes::newsletter::handle_newsletter_subscribe))
        .route("/api/v1/newsletter/unsubscribe", post(routes::newsletter::handle_newsletter_unsubscribe))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // 5. Start Server
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    info!("World of Unreal ID listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
