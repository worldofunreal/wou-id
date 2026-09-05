use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use wou_core::PlayerAccount;

use crate::state::AppState;

// Hyper calls this on every start to validate the stored JWT.
pub async fn handle_me(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<PlayerAccount>, (StatusCode, Json<serde_json::Value>)> {
    match state.storage.get_account_by_id(&auth.account_id).await {
        Ok(Some(account)) => Ok(Json(account)),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Account not found for session"})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub status: &'static str,
    pub account: PlayerAccount,
    pub session_token: String,
}

// Remember-me: re-issue a fresh 30d JWT when the old one still verifies.
pub async fn handle_refresh(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<RefreshResponse>, (StatusCode, Json<serde_json::Value>)> {
    let account = state
        .storage
        .get_account_by_id(&auth.account_id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Account not found for session"})),
            )
        })?;

    let token = state
        .jwt
        .issue_token(
            &account.id,
            &account.display_name,
            account.email.clone(),
            auth.claims.context,
            86400 * 30,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(RefreshResponse {
        status: "authenticated",
        account,
        session_token: token,
    }))
}

// Stateless JWT: server has nothing to revoke yet (Valkey blocklist is a future step).
// Endpoint exists so clients share one logout path and we can add revoke without breaking them.
pub async fn handle_logout() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "logged_out"}))
}
