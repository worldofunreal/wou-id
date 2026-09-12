use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use wou_core::{AuthProvider, GameContext, PlayerAccount, SESSION_TTL_SECONDS};

use crate::routes::guard::verified_owner;
use crate::state::AppState;

/// OAuth redirect targets are pinned: the central hub plus explicit per-game
/// callbacks (one-click login without hub bounce) plus loopback (dev).
/// Every non-loopback entry must ALSO be registered in the provider consoles
/// (Google Cloud Console / Discord Dev Portal authorized redirect URIs).
/// Providers enforce their own allowlists; this is defense in depth.
pub const OAUTH_HUB_CALLBACK: &str = "https://worldofunreal.com/auth/callback";

/// Direct game callbacks. To add a game: append its
/// `https://<domain>/auth/callback` here AND register the exact same URI
/// in the provider consoles, otherwise providers reject with redirect_uri_mismatch.
pub const OAUTH_GAME_CALLBACKS: &[&str] = &["https://shadowsofwar.io/auth/callback"];

fn redirect_allowed(uri: &str) -> bool {
    if uri == OAUTH_HUB_CALLBACK || OAUTH_GAME_CALLBACKS.contains(&uri) {
        return true;
    }
    let host = uri
        .split("://")
        .nth(1)
        .unwrap_or(uri)
        .split('/')
        .next()
        .unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    host == "localhost" || host == "127.0.0.1"
}

#[derive(Deserialize)]
pub struct OAuthLoginQuery {
    pub redirect_uri: Option<String>,
    pub redirect_url: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

pub async fn handle_oauth_login(
    Path(provider_str): Path<String>,
    Query(query): Query<OAuthLoginQuery>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let provider = match provider_str.to_lowercase().as_str() {
        "discord" => AuthProvider::Discord,
        "google" => AuthProvider::Google,
        "twitter" | "x" => AuthProvider::Twitter,
        "meta" | "facebook" => AuthProvider::Meta,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Unsupported OAuth provider: {provider_str}")})),
            ))
        }
    };

    // Fail closed: no silent mock credentials. Unset env = 503, never a
    // redirect built with a bogus client_id.
    let client_id_env = format!("WOU_{}_CLIENT_ID", provider.as_str().to_uppercase());
    let client_id = std::env::var(&client_id_env).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": format!("OAuth provider not configured: {provider_str}")})),
        )
    })?;
    let redirect_uri = query
        .redirect_uri
        .or(query.redirect_url)
        .unwrap_or_else(|| OAUTH_HUB_CALLBACK.into());
    if !redirect_allowed(&redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Unsupported redirect_uri"})),
        ));
    }
    let state_str = query.state.unwrap_or_else(|| "default_state".into());

    let auth_url = state
        .oauth
        .build_authorization_url(&provider, &client_id, &redirect_uri, &state_str)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(axum::response::Redirect::temporary(&auth_url))
}

#[derive(Deserialize)]
pub struct OAuthCallbackPayload {
    pub code: String,
    pub redirect_uri: Option<String>,
    pub redirect_url: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub context: GameContext,
}

#[derive(Serialize)]
pub struct OAuthCallbackResponse {
    pub status: &'static str,
    pub account: PlayerAccount,
    pub session_token: String,
    pub is_new_account: bool,
}

pub async fn handle_oauth_callback(
    Path(provider_str): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OAuthCallbackPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let provider = match provider_str.to_lowercase().as_str() {
        "discord" => AuthProvider::Discord,
        "google" => AuthProvider::Google,
        "twitter" | "x" => AuthProvider::Twitter,
        "meta" | "facebook" => AuthProvider::Meta,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Unsupported OAuth provider: {provider_str}")})),
            ))
        }
    };

    let client_id_env = format!("WOU_{}_CLIENT_ID", provider.as_str().to_uppercase());
    let client_secret_env = format!("WOU_{}_CLIENT_SECRET", provider.as_str().to_uppercase());
    // Fail closed (see login handler): unset secrets = 503, never mock exchange.
    let client_id = std::env::var(&client_id_env).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": format!("OAuth provider not configured: {provider_str}")})),
        )
    })?;
    let client_secret = std::env::var(&client_secret_env).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": format!("OAuth provider not configured: {provider_str}")})),
        )
    })?;

    let redirect_uri = payload
        .redirect_uri
        .or(payload.redirect_url)
        .unwrap_or_else(|| OAUTH_HUB_CALLBACK.into());
    if !redirect_allowed(&redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Unsupported redirect_uri"})),
        ));
    }

    // Exchange authorization code for verified user profile info
    let user_info = state
        .oauth
        .exchange_code_for_user(
            &provider,
            &payload.code,
            &client_id,
            &client_secret,
            &redirect_uri,
        )
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": e.to_string()}))))?;

    // Check if account already exists with this linked social identity
    let existing_by_identity = state
        .storage
        .find_account_by_identity(&provider, &user_info.external_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let (mut final_account, is_new) = if let Some(mut existing) = existing_by_identity {
        if let Some(ref avatar) = user_info.avatar_url {
            existing.profile.avatar_url = Some(avatar.clone());
        }
        existing.updated_at = chrono::Utc::now().timestamp() as u64;
        let _ = state.storage.save_account(&existing).await;
        (existing, false)
    } else {
        // Merge into the caller's own session account only (ownership proof).
        // Otherwise mint fresh: a verified Google login must never adopt an
        // arbitrary account id supplied by the client.
        let target_id = match payload.account_id.clone() {
            Some(id)
                if state.storage.get_account_by_id(&id).await.ok().flatten().is_some()
                    && verified_owner(&headers, &state, &id).await =>
            {
                id
            }
            _ => uuid::Uuid::new_v4().to_string(),
        };

        let wallets = wou_crypto::web3::derive_embedded_wallets(&target_id, &state.vault_seed);
        let mut account = match state.storage.get_account_by_id(&target_id).await {
            Ok(Some(anon)) => anon,
            _ => {
                PlayerAccount::new_with_wallets(target_id, None, user_info.display_name.clone(), wallets)
            }
        };

        if let Some(ref email) = user_info.email {
            if account.email.is_none() {
                account.email = Some(email.clone());
            }
        }
        if let Some(ref avatar) = user_info.avatar_url {
            account.profile.avatar_url = Some(avatar.clone());
        }
        if let Some(ref name) = user_info.display_name {
            if account.display_name.starts_with("Commander_") {
                account.display_name = name.clone();
            }
        }

        account.link_identity(provider.clone(), user_info.external_id.clone());
        state
            .storage
            .save_account(&account)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

        (account, true)
    };

    // One-time welcome when the provider supplied an email (provider-verified).
    // Best-effort: welcome failure never fails auth; flag makes it idempotent.
    if is_new && !final_account.welcome_sent {
        if let Some(ref email) = final_account.email.clone() {
            final_account.welcome_sent = true;
            final_account.updated_at = chrono::Utc::now().timestamp() as u64;
            if state.storage.save_account(&final_account).await.is_ok() {
                let mailer = state.mailer.clone();
                let ctx = payload.context;
                let to = email.clone();
                let name = final_account.display_name.clone();
                tokio::spawn(async move {
                    let _ = mailer.send_welcome(&to, ctx, &name).await;
                });
            }
        }
    }

    let session_token = state
        .jwt
        .issue_token(
            &final_account.id,
            &final_account.display_name,
            final_account.email.clone(),
            payload.context,
            SESSION_TTL_SECONDS,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    info!(
        "OAuth2 login successful for provider {:?} (ID: {}) -> Account {}",
        provider, user_info.external_id, final_account.id
    );

    Ok(Json(OAuthCallbackResponse {
        status: "authenticated",
        account: final_account,
        session_token,
        is_new_account: is_new,
    }))
}
