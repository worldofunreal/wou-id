use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use wou_core::PlayerAccount;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct UpdateDisplayNamePayload {
    pub display_name: String,
}

pub async fn handle_get_profile(
    Path(account_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<PlayerAccount>, (StatusCode, Json<serde_json::Value>)> {
    match state.storage.get_account_by_id(&account_id).await {
        Ok(Some(account)) => Ok(Json(account)),
        Ok(None) => Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"})))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))),
    }
}

pub async fn handle_update_display_name(
    Path(account_id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<UpdateDisplayNamePayload>,
) -> Result<Json<PlayerAccount>, (StatusCode, Json<serde_json::Value>)> {
    let clean_name = payload.display_name.trim();
    if clean_name.is_empty() || clean_name.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Display name must be between 1 and 32 characters"})),
        ));
    }

    let mut account = state
        .storage
        .get_account_by_id(&account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;

    account.display_name = clean_name.to_string();
    account.updated_at = chrono::Utc::now().timestamp() as u64;

    state
        .storage
        .save_account(&account)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(account))
}
