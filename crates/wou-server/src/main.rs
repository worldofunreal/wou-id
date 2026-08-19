mod routes;
mod state;

use axum::{
    routing::{get, post, put},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wou_crypto::JwtManager;
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

    let jwt_secret = std::env::var("WOU_JWT_SECRET").unwrap_or_else(|_| {
        "wou_id_default_development_secret_key_change_in_production_environment_12345678".into()
    });

    let smtp_host = std::env::var("WOU_SMTP_HOST").unwrap_or_else(|_| "mail.worldofunreal.com".into());
    let smtp_port: u16 = std::env::var("WOU_SMTP_PORT")
        .unwrap_or_else(|_| "465".into())
        .parse()
        .unwrap_or(465);
    let smtp_user = std::env::var("WOU_SMTP_USER").unwrap_or_else(|_| "no-reply@worldofunreal.com".into());
    let smtp_password = std::env::var("WOU_SMTP_PASSWORD").unwrap_or_else(|_| "ni*5lC673XuaPjDmPk3QAgqd".into());

    let otp_expiry_seconds: u64 = std::env::var("WOU_OTP_EXPIRY_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse()
        .unwrap_or(600);

    // 3. Initialize Storage & Stalwart Mailer
    let storage = WouStorage::new(&redis_url, &redb_path)?;
    let mailer_config = StalwartMailerConfig {
        smtp_host,
        smtp_port,
        smtp_user,
        smtp_password,
    };
    let mailer = StalwartMailer::new(mailer_config)?;
    let jwt = Arc::new(JwtManager::new(&jwt_secret));

    let state = AppState {
        storage,
        mailer,
        jwt,
        otp_expiry_seconds,
    };

    // 4. Configure CORS & Routes
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Health Check
        .route("/health", get(|| async { "WOU-ID Online 200 OK" }))
        // Anonymous-First Auth
        .route("/api/v1/auth/anonymous", post(routes::anonymous::handle_anonymous))
        // Stalwart OTP Registration & Verification
        .route("/api/v1/auth/otp/request", post(routes::otp::handle_request_otp))
        .route("/api/v1/auth/otp/verify", post(routes::otp::handle_verify_otp))
        // Multi-Provider Linking
        .route("/api/v1/auth/link/crazygames", post(routes::link::handle_link_crazygames))
        .route("/api/v1/auth/link/ethereum", post(routes::link::handle_link_ethereum))
        .route("/api/v1/auth/link/solana", post(routes::link::handle_link_solana))
        // Profile Management
        .route("/api/v1/user/profile/:id", get(routes::profile::handle_get_profile))
        .route("/api/v1/user/profile/:id/name", put(routes::profile::handle_update_display_name))
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
