use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;
use wou_core::{AuthProvider, GameContext, PlayerAccount, SESSION_TTL_SECONDS, canonical_email};

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
const OAUTH_STATE_TTL_SECONDS: u64 = 600;

#[derive(Serialize)]
pub struct OAuthCallbackConfig {
    pub hub_callback: &'static str,
    pub game_callbacks: &'static [&'static str],
}

pub async fn handle_oauth_config() -> impl IntoResponse {
    Json(OAuthCallbackConfig {
        hub_callback: OAUTH_HUB_CALLBACK,
        game_callbacks: OAUTH_GAME_CALLBACKS,
    })
}

#[derive(Deserialize, Serialize)]
struct OAuthStateRecord {
    provider: String,
    redirect_uri: String,
    #[serde(default)]
    code_challenge: Option<String>,
}

fn oauth_state_key(state: &str) -> String {
    let digest = Sha256::digest(state.as_bytes());
    format!("wou_oauth_state:{}", hex::encode(digest))
}

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
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
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
    let state_str = query
        .state
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "OAuth state is required"})),
            )
        })?;
    let code_challenge = query
        .code_challenge
        .filter(|value| !value.trim().is_empty());
    if matches!(provider, AuthProvider::Twitter)
        && (code_challenge.is_none()
            || query.code_challenge_method.as_deref() != Some("S256"))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "X OAuth requires S256 PKCE"})),
        ));
    }

    let auth_url = state
        .oauth
        .build_authorization_url(&provider, &client_id, &redirect_uri, &state_str, code_challenge.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let state_record = serde_json::to_string(&OAuthStateRecord {
        provider: provider.as_str().to_string(),
        redirect_uri: redirect_uri.clone(),
        code_challenge,
    })
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    state
        .storage
        .save_cache_string(&oauth_state_key(&state_str), &state_record, OAUTH_STATE_TTL_SECONDS)
        .await
        .map_err(|e| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("OAuth state storage unavailable: {e}")})),
            )
        })?;

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
    pub state: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
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

    let state_value = payload
        .state
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "OAuth state is required"})),
            )
        })?;
    let state_record_raw = state
        .storage
        .take_cache_string(&oauth_state_key(state_value))
        .await
        .map_err(|e| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": format!("OAuth state storage unavailable: {e}")})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "OAuth state expired or already used"})),
            )
        })?;
    let state_record: OAuthStateRecord = serde_json::from_str(&state_record_raw).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("OAuth state record invalid: {e}")})),
        )
    })?;
    if state_record.provider != provider.as_str() || state_record.redirect_uri != redirect_uri {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "OAuth state does not match this callback"})),
        ));
    }
    if state_record.code_challenge.is_some() && payload.code_verifier.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "OAuth PKCE verifier is required"})),
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
            payload.code_verifier.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": e.to_string()}))))?;

    // Check if account already exists with this linked social identity
    let existing_by_identity = state
        .storage
        .find_account_by_identity(&provider, &user_info.external_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let verified_email = user_info
        .email_verified
        .then(|| user_info.email.as_deref().map(canonical_email))
        .flatten();
    let existing_by_email = if let Some(email) = verified_email.as_deref() {
        state
            .storage
            .find_account_by_email(email)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
    } else {
        None
    };

    if let (Some(by_identity), Some(by_email)) = (&existing_by_identity, &existing_by_email) {
        if by_identity.id != by_email.id {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "this verified email and provider identity belong to different accounts"
                })),
            ));
        }
    }

    let (mut final_account, is_new) = if let Some(mut existing) = existing_by_identity {
        if let Some(email) = verified_email.as_deref() {
            if let Some(account_email) = existing.email.as_deref() {
                if canonical_email(account_email) != email {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({"error": "account already has a different verified email"})),
                    ));
                }
            }
            existing.email = Some(email.to_string());
        }
        if let Some(ref avatar) = user_info.avatar_url {
            existing.profile.avatar_url = Some(avatar.clone());
        }
        existing.updated_at = chrono::Utc::now().timestamp() as u64;
        state
            .storage
            .save_account(&existing)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
        (existing, false)
    } else if let Some(mut existing) = existing_by_email {
        existing.link_identity(provider.clone(), user_info.external_id.clone());
        if let Some(ref avatar) = user_info.avatar_url {
            existing.profile.avatar_url = Some(avatar.clone());
        }
        if let Some(ref name) = user_info.display_name {
            if existing.display_name.starts_with("Commander_") {
                existing.display_name = name.clone();
            }
        }
        state
            .storage
            .save_account(&existing)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
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

        if let Some(email) = verified_email {
            if let Some(account_email) = account.email.as_deref() {
                if canonical_email(account_email) != email {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({"error": "account already has a different verified email"})),
                    ));
                }
            }
            account.email = Some(email);
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
