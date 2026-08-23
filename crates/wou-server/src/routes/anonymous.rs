use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wou_core::{GameContext, PlayerAccount};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct AnonymousRequest {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub context: GameContext,
}

#[derive(Serialize)]
pub struct AnonymousResponse {
    pub account: PlayerAccount,
    pub session_token: String,
}

pub async fn handle_anonymous(
    State(state): State<AppState>,
    Json(payload): Json<AnonymousRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // 1. If account_id provided, check if it already exists
    if let Some(ref acc_id) = payload.account_id {
        if let Ok(Some(existing_account)) = state.storage.get_account_by_id(acc_id).await {
            let session_token = state
                .jwt
                .issue_token(
                    &existing_account.id,
                    &existing_account.display_name,
                    existing_account.email.clone(),
                    payload.context,
                    86400 * 30, // 30 days
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

            return Ok(Json(AnonymousResponse {
                account: existing_account,
                session_token,
            }));
        }
    }

    // 2. Generate a fresh canonical account with auto-embedded multi-chain wallets
    let new_id = payload.account_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let wallets = wou_crypto::web3::derive_embedded_wallets(&new_id, "wou-sovereign-vault-secret-v1");
    let account = PlayerAccount::new_with_wallets(new_id, None, payload.display_name, wallets);

    state
        .storage
        .save_account(&account)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let session_token = state
        .jwt
        .issue_token(
            &account.id,
            &account.display_name,
            account.email.clone(),
            payload.context,
            86400 * 30,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(AnonymousResponse {
        account,
        session_token,
    }))
}
