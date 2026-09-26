use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wou_core::{AuthProvider, PlayerAccount, canonical_email};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct ResolveIdentityRequest {
    provider: String,
    external_id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
}

#[derive(Deserialize)]
pub struct ResetHumanAccountsRequest {
    confirmation: String,
    #[serde(default = "default_dry_run")]
    dry_run: bool,
}

fn default_dry_run() -> bool {
    true
}

#[derive(Serialize)]
struct ResolveIdentityResponse {
    account_id: String,
    created: bool,
}

fn provider_from_wire(value: &str) -> Option<AuthProvider> {
    match value.trim() {
        "crazygames" => Some(AuthProvider::CrazyGames),
        "gamecenter" => Some(AuthProvider::Custom("gamecenter".to_string())),
        "playgames" => Some(AuthProvider::Custom("playgames".to_string())),
        "poki" => Some(AuthProvider::Poki),
        "steam" => Some(AuthProvider::Custom("steam".to_string())),
        "epic" => Some(AuthProvider::Custom("epic".to_string())),
        _ => None,
    }
}

fn authorized(headers: &HeaderMap, secret: Option<&str>) -> bool {
    let Some(secret) = secret else { return false };
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value.trim() == secret)
}

pub async fn handle_resolve_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ResolveIdentityRequest>,
) -> impl IntoResponse {
    if state.wou_sow_identity_secret.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "identity bridge is not configured"})),
        )
            .into_response();
    }
    if !authorized(&headers, state.wou_sow_identity_secret.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    let Some(provider) = provider_from_wire(&payload.provider) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unsupported provider"})),
        )
            .into_response();
    };
    let external_id = payload.external_id.trim();
    if external_id.is_empty() || external_id.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid external identity"})),
        )
            .into_response();
    }

    let account_id = Uuid::new_v4().to_string();
    let wallets = wou_crypto::web3::derive_embedded_wallets(&account_id, &state.vault_seed);
    let mut account = PlayerAccount::new_with_wallets(
        account_id,
        None,
        payload.display_name.filter(|value| !value.trim().is_empty()),
        wallets,
    );
    if payload.email_verified {
        if let Some(email) = payload.email.as_deref().filter(|value| !value.trim().is_empty()) {
            account.email = Some(canonical_email(email));
        }
    }
    account.link_identity(provider.clone(), external_id.to_string());

    match state
        .storage
        .resolve_or_create_service_identity(provider, external_id, account)
        .await
    {
        Ok((account, created)) => (
            StatusCode::OK,
            Json(ResolveIdentityResponse {
                account_id: account.id,
                created,
            }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn handle_reset_human_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ResetHumanAccountsRequest>,
) -> impl IntoResponse {
    if state.wou_sow_identity_secret.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "identity bridge is not configured"})),
        )
            .into_response();
    }
    if !authorized(&headers, state.wou_sow_identity_secret.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    if payload.confirmation != "RESET_HUMAN_TEST_DATA" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "exact confirmation is required"})),
        )
            .into_response();
    }
    match state.storage.reset_human_accounts(payload.dry_run).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct RecordActivityRequest {
    pub account_id: String,
    pub activity_type: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub game: wou_core::GameContext,
}

/// Server-to-server activity recording (same trust level as identity/resolve):
/// a game server reports a highlight event for one of its players. Bearer auth
/// with the shared bridge secret; the feed renders by activity_type, so
/// title/description stay free-form English fallbacks.
pub async fn handle_record_activity_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RecordActivityRequest>,
) -> impl IntoResponse {
    if state.wou_sow_identity_secret.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "identity bridge is not configured"})),
        )
            .into_response();
    }
    if !authorized(&headers, state.wou_sow_identity_secret.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    let activity_type = payload.activity_type.trim();
    if activity_type.is_empty()
        || activity_type.len() > 64
        || payload.title.trim().is_empty()
        || payload.title.len() > 140
        || payload.description.len() > 280
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid activity payload"})),
        )
            .into_response();
    }
    let account = match state.storage.get_account_by_id(&payload.account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "account not found"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let activity = wou_core::SocialActivity {
        id: Uuid::new_v4().to_string(),
        account_id: account.id.clone(),
        username: account.username.clone(),
        display_name: account.display_name.clone(),
        avatar_url: account.profile.avatar_url.clone(),
        activity_type: activity_type.to_string(),
        title: payload.title,
        description: payload.description,
        game: payload.game,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    match state.storage.record_social_activity(&activity).await {
        Ok(()) => (StatusCode::CREATED, Json(activity)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpsertTokensRequest {
    #[serde(default)]
    pub collection: Option<wou_core::Collection>,
    pub tokens: Vec<wou_core::TokenType>,
}

/// Bridge-only catalog maintenance: create a collection once (optional),
/// then register new cards or refresh card metadata
/// (name/description/image/attributes) on existing ones. Supply counters and
/// owned instances are never modified. Same trust level as identity/resolve:
/// shared bridge secret bearer, no browser session.
pub async fn handle_upsert_tokens_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<UpsertTokensRequest>,
) -> impl IntoResponse {
    if state.wou_sow_identity_secret.is_none() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "identity bridge is not configured"})),
        )
            .into_response();
    }
    if !authorized(&headers, state.wou_sow_identity_secret.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    if payload.tokens.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "tokens required"})),
        )
            .into_response();
    }
    if let Some(collection) = payload.collection {
        if let Err(e) = state.storage.ensure_collection(collection).await {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    let mut applied = Vec::with_capacity(payload.tokens.len());
    for token in payload.tokens {
        match state.storage.upsert_token(token).await {
            Ok(tok) => applied.push(tok),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response()
            }
        }
    }
    (StatusCode::OK, Json(serde_json::json!({ "tokens": applied }))).into_response()
}
