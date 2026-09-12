use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use wou_core::{PlayerAccount, PublicProfile};

use crate::routes::guard::{client_ip, verified_owner};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct UpdateProfilePayload {
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub country: Option<String>,
}

#[derive(Deserialize)]
pub struct CheckUsernameQuery {
    #[serde(default)]
    pub current_id: Option<String>,
}

#[derive(Serialize)]
pub struct CheckUsernameResponse {
    pub username: String,
    pub available: bool,
}

/// Throttle unauthenticated enumeration oracles (NAT-friendly IP ceilings,
/// same intake policy as anonymous/OTP). Over-limit = 429, never a data leak.
async fn gate_oracle(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = state.storage.tally_ip(&client_ip(headers)).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }
    Ok(())
}

pub async fn handle_get_profile(
    Path(account_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PublicProfile>, (StatusCode, Json<serde_json::Value>)> {
    // Owner (valid session for this id) skips the throttle; everyone else is
    // gated. Response is always the public card (owners use /me for full data).
    if !verified_owner(&headers, &state, &account_id).await {
        gate_oracle(&state, &headers).await?;
    }
    match state.storage.get_account_by_id(&account_id).await {
        Ok(Some(account)) => Ok(Json(PublicProfile::from(&account))),
        Ok(None) => Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"})))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))),
    }
}

pub async fn handle_get_by_username(
    Path(username): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<PublicProfile>, (StatusCode, Json<serde_json::Value>)> {
    gate_oracle(&state, &headers).await?;
    match state.storage.find_account_by_username(&username).await {
        Ok(Some(account)) => Ok(Json(PublicProfile::from(&account))),
        Ok(None) => Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Player handle not found"})))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))),
    }
}

pub async fn handle_check_username(
    Path(username): Path<String>,
    Query(query): Query<CheckUsernameQuery>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CheckUsernameResponse>, (StatusCode, Json<serde_json::Value>)> {
    gate_oracle(&state, &headers).await?;
    let current_id = query.current_id.unwrap_or_default();
    let available = state
        .storage
        .is_username_available(&username, &current_id)
        .await
        .unwrap_or(false);

    Ok(Json(CheckUsernameResponse {
        username,
        available,
    }))
}

pub async fn handle_update_profile(
    auth: crate::AuthSession,
    Path(account_id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<UpdateProfilePayload>,
) -> Result<Json<PlayerAccount>, (StatusCode, Json<serde_json::Value>)> {
    if auth.account_id != account_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Forbidden: You cannot modify another player's profile"})),
        ));
    }

    let mut account = state
        .storage
        .get_account_by_id(&account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;

    // 1. Update Username Handle if changed
    if let Some(new_user) = payload.username {
        let clean_user = new_user.trim().trim_start_matches('@').to_lowercase();
        if clean_user != account.username.to_lowercase() {
            let available = state
                .storage
                .is_username_available(&clean_user, &account.id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

            if !available {
                return Err((
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({"error": format!("Username @{clean_user} is already taken or invalid.")})),
                ));
            }
            account.username = clean_user;
        }
    }

    // 2. Update Display Name
    if let Some(new_name) = payload.display_name {
        let clean = new_name.trim();
        if !clean.is_empty() && clean.len() <= 40 {
            account.display_name = clean.to_string();
        }
    }

    // 3. Update Bio
    if let Some(new_bio) = payload.bio {
        account.profile.bio = Some(new_bio.trim().to_string());
    }

    // 4. Update Avatar URL
    if let Some(new_avatar) = payload.avatar_url {
        account.profile.avatar_url = Some(new_avatar.trim().to_string());
    }

    // 5. Update Banner URL
    if let Some(new_banner) = payload.banner_url {
        account.profile.banner_url = Some(new_banner.trim().to_string());
    }

    // 6. Update Country
    if let Some(new_country) = payload.country {
        account.profile.country = Some(new_country.trim().to_string());
    }

    account.updated_at = chrono::Utc::now().timestamp() as u64;

    state
        .storage
        .save_account(&account)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(account))
}

#[derive(Deserialize)]
pub struct SearchPlayersQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default = "default_search_limit")]
    pub limit: usize,
}

fn default_search_limit() -> usize {
    10
}

pub async fn handle_search_players(
    Query(query): Query<SearchPlayersQuery>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<wou_core::PlayerSearchResult>>, (StatusCode, Json<serde_json::Value>)> {
    gate_oracle(&state, &headers).await?;
    let results = state
        .storage
        .search_players(&query.q, query.limit.min(50))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(results))
}

