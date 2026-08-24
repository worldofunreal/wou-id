use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use wou_core::{Clan, ClanMember, ClanRole};

use crate::{state::AppState, AuthSession};

#[derive(Deserialize)]
pub struct CreateClanPayload {
    pub tag: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct ListClansQuery {
    #[serde(default = "default_list_limit")]
    pub limit: usize,
}

fn default_list_limit() -> usize {
    20
}

#[derive(Serialize)]
pub struct ClanDetailsResponse {
    pub clan: Clan,
    pub members: Vec<ClanMember>,
}

pub async fn handle_create_clan(
    auth: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<CreateClanPayload>,
) -> Result<Json<Clan>, (StatusCode, Json<serde_json::Value>)> {
    let tag = payload.tag.trim().to_uppercase();
    let name = payload.name.trim().to_string();

    // 1. Validate Tag (2-5 alphanumeric chars)
    if tag.len() < 2 || tag.len() > 5 || !tag.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Clan tag must be 2 to 5 alphanumeric characters (e.g. SOW, VOID, WOU)"})),
        ));
    }

    // 2. Validate Name (3-32 chars)
    if name.len() < 3 || name.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Clan name must be between 3 and 32 characters"})),
        ));
    }

    // 3. Fetch caller account
    let mut account = state
        .storage
        .get_account_by_id(&auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "Account not found"}))))?;

    let now = chrono::Utc::now().timestamp() as u64;

    let clan = Clan {
        tag: tag.clone(),
        name: name.clone(),
        description: payload.description.unwrap_or_default().trim().to_string(),
        leader_id: account.id.clone(),
        leader_username: account.username.clone(),
        avatar_url: None,
        banner_url: None,
        member_count: 1,
        created_at: now,
    };

    let animal_emoji = account
        .profile
        .custom_attributes
        .get("animal_emoji")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let leader_member = ClanMember {
        account_id: account.id.clone(),
        username: account.username.clone(),
        display_name: account.display_name.clone(),
        avatar_url: account.profile.avatar_url.clone(),
        animal_emoji,
        role: ClanRole::Leader,
        joined_at: now,
    };

    // 4. Save to Storage
    state
        .storage
        .create_clan(&clan, &leader_member)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))))?;

    // 5. Update Leader's clan fields
    account.clan_tag = Some(tag.clone());
    account.clan_name = Some(name.clone());
    account.updated_at = now;
    let _ = state.storage.save_account(&account).await;

    Ok(Json(clan))
}

pub async fn handle_get_clan(
    Path(tag): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ClanDetailsResponse>, (StatusCode, Json<serde_json::Value>)> {
    let clean_tag = tag.trim().to_uppercase();

    let clan = state
        .storage
        .get_clan(&clean_tag)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": format!("Clan [{clean_tag}] not found")})) ))?;

    let members = state
        .storage
        .get_clan_members(&clean_tag)
        .await
        .unwrap_or_default();

    Ok(Json(ClanDetailsResponse { clan, members }))
}

pub async fn handle_list_clans(
    Query(query): Query<ListClansQuery>,
    State(state): State<AppState>,
) -> Result<Json<Vec<Clan>>, (StatusCode, Json<serde_json::Value>)> {
    let clans = state
        .storage
        .list_clans(query.limit.min(50))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?;

    Ok(Json(clans))
}

pub async fn handle_join_clan(
    auth: AuthSession,
    Path(tag): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let clean_tag = tag.trim().to_uppercase();

    let clan = state
        .storage
        .get_clan(&clean_tag)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": format!("Clan [{clean_tag}] not found")})) ))?;

    let mut account = state
        .storage
        .get_account_by_id(&auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "Account not found"}))))?;

    let now = chrono::Utc::now().timestamp() as u64;

    let animal_emoji = account
        .profile
        .custom_attributes
        .get("animal_emoji")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let member = ClanMember {
        account_id: account.id.clone(),
        username: account.username.clone(),
        display_name: account.display_name.clone(),
        avatar_url: account.profile.avatar_url.clone(),
        animal_emoji,
        role: ClanRole::Member,
        joined_at: now,
    };

    state
        .storage
        .join_clan(&clean_tag, &member)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))))?;

    account.clan_tag = Some(clean_tag.clone());
    account.clan_name = Some(clan.name);
    account.updated_at = now;
    let _ = state.storage.save_account(&account).await;

    Ok(Json(json!({
        "success": true,
        "clan_tag": clean_tag
    })))
}

pub async fn handle_leave_clan(
    auth: AuthSession,
    Path(tag): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let clean_tag = tag.trim().to_uppercase();

    state
        .storage
        .leave_clan(&clean_tag, &auth.account_id)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))))?;

    if let Ok(Some(mut account)) = state.storage.get_account_by_id(&auth.account_id).await {
        if account.clan_tag.as_deref() == Some(&clean_tag) {
            account.clan_tag = None;
            account.clan_name = None;
            account.updated_at = chrono::Utc::now().timestamp() as u64;
            let _ = state.storage.save_account(&account).await;
        }
    }

    Ok(Json(json!({
        "success": true,
        "message": format!("Successfully left clan [{clean_tag}]")
    })))
}
