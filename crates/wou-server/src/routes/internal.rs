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
