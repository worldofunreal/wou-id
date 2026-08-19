use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::info;
use wou_core::{AuthProvider, GameContext, PlayerAccount};
use wou_crypto::{verify_crazygames_token, verify_ethereum_signature, verify_solana_signature};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct LinkCrazyGamesPayload {
    pub account_id: String,
    pub token: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub context: GameContext,
}

#[derive(Deserialize)]
pub struct LinkWeb3Payload {
    pub account_id: String,
    pub address_or_pubkey: String,
    pub message: String,
    pub signature: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub context: GameContext,
}

#[derive(Serialize)]
pub struct LinkResponse {
    pub status: &'static str,
    pub account: PlayerAccount,
}

pub async fn handle_link_crazygames(
    State(state): State<AppState>,
    Json(payload): Json<LinkCrazyGamesPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let verified_user_id = verify_crazygames_token(&payload.token)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": e.to_string()}))))?;

    let mut account = state
        .storage
        .get_account_by_id(&payload.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;

    account.link_identity(AuthProvider::CrazyGames, verified_user_id.clone());
    state.storage.save_account(&account).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
    })?;

    info!("CrazyGames ID {} linked to account {}", verified_user_id, account.id);

    Ok(Json(LinkResponse {
        status: "linked",
        account,
    }))
}

pub async fn handle_link_ethereum(
    State(state): State<AppState>,
    Json(payload): Json<LinkWeb3Payload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let is_valid = verify_ethereum_signature(&payload.address_or_pubkey, &payload.message, &payload.signature)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))))?;

    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid Ethereum cryptographic signature"})),
        ));
    }

    let mut account = state
        .storage
        .get_account_by_id(&payload.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;

    account.link_identity(AuthProvider::Ethereum, payload.address_or_pubkey.clone());
    state.storage.save_account(&account).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
    })?;

    info!("Ethereum address {} linked to account {}", payload.address_or_pubkey, account.id);

    Ok(Json(LinkResponse {
        status: "linked",
        account,
    }))
}

pub async fn handle_link_solana(
    State(state): State<AppState>,
    Json(payload): Json<LinkWeb3Payload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let is_valid = verify_solana_signature(&payload.address_or_pubkey, &payload.message, &payload.signature)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))))?;

    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid Solana cryptographic signature"})),
        ));
    }

    let mut account = state
        .storage
        .get_account_by_id(&payload.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;

    account.link_identity(AuthProvider::Solana, payload.address_or_pubkey.clone());
    state.storage.save_account(&account).await.map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
    })?;

    info!("Solana pubkey {} linked to account {}", payload.address_or_pubkey, account.id);

    Ok(Json(LinkResponse {
        status: "linked",
        account,
    }))
}
