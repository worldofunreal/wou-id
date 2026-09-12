use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wou_core::{GameContext, PlayerAccount, SESSION_TTL_SECONDS};

use crate::routes::guard::{client_ip, verified_owner};
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
    headers: HeaderMap,
    Json(payload): Json<AnonymousRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Protection mode + per-IP gate (same intake policy as OTP).
    if state.storage.protection_mode().await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Service in protection mode, try again later"})),
        ));
    }
    if let Err(e) = state.storage.tally_ip(&client_ip(&headers)).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }
    // 1. Resume only with ownership proof: a valid JWT for that same account.
    // A bare client-supplied id never mints a session (account-takeover hole).
    if let Some(ref acc_id) = payload.account_id {
        if state.storage.get_account_by_id(acc_id).await.ok().flatten().is_some() {
            if !verified_owner(&headers, &state, acc_id).await {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "Existing account requires its session token to resume"})),
                ));
            }
            let existing_account = state.storage.get_account_by_id(acc_id).await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
                .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;
            let session_token = state
                .jwt
                .issue_token(
                    &existing_account.id,
                    &existing_account.display_name,
                    existing_account.email.clone(),
                    payload.context,
                    SESSION_TTL_SECONDS,
                )
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

            return Ok(Json(AnonymousResponse {
                account: existing_account,
                session_token,
            }));
        }
    }

    // 2. Fresh account: server-minted UUID (client-chosen ids are ignored,
    // they enable id-squatting) with auto-embedded multi-chain wallets.
    let new_id = Uuid::new_v4().to_string();
    let wallets = wou_crypto::web3::derive_embedded_wallets(&new_id, &state.vault_seed);
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
            SESSION_TTL_SECONDS,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(AnonymousResponse {
        account,
        session_token,
    }))
}
