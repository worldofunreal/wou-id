use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use wou_core::{GameContext, SocialActivity};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct FeedQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

#[derive(Deserialize)]
pub struct RecordActivityPayload {
    #[serde(default)]
    #[allow(dead_code)]
    pub account_id: Option<String>,
    pub activity_type: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub game: GameContext,
}

#[derive(Serialize)]
pub struct FollowResponse {
    pub status: &'static str,
    pub follower_id: String,
    pub target_id: String,
}

#[derive(Serialize)]
pub struct SocialCountsResponse {
    pub account_id: String,
    pub followers: Vec<String>,
    pub following: Vec<String>,
}

pub async fn handle_follow_user(
    auth: crate::AuthSession,
    Path(target_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<FollowResponse>, (StatusCode, Json<serde_json::Value>)> {
    if auth.account_id == target_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Cannot follow yourself"})),
        ));
    }

    state
        .storage
        .follow_user(&auth.account_id, &target_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(FollowResponse {
        status: "following",
        follower_id: auth.account_id,
        target_id,
    }))
}

pub async fn handle_unfollow_user(
    auth: crate::AuthSession,
    Path(target_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<FollowResponse>, (StatusCode, Json<serde_json::Value>)> {
    state
        .storage
        .unfollow_user(&auth.account_id, &target_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(FollowResponse {
        status: "unfollowed",
        follower_id: auth.account_id,
        target_id,
    }))
}

pub async fn handle_get_social_graph(
    Path(account_id): Path<String>,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<SocialCountsResponse>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = state.storage.tally_ip(&crate::routes::guard::client_ip(&headers)).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }
    let followers = state.storage.get_followers(&account_id).await.unwrap_or_default();
    let following = state.storage.get_following(&account_id).await.unwrap_or_default();

    Ok(Json(SocialCountsResponse {
        account_id,
        followers,
        following,
    }))
}

pub async fn handle_get_global_feed(
    Query(query): Query<FeedQuery>,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<SocialActivity>>, (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = state.storage.tally_ip(&crate::routes::guard::client_ip(&headers)).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }
    let feed = state
        .storage
        .get_social_feed(query.limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(feed))
}

pub async fn handle_record_activity(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<RecordActivityPayload>,
) -> Result<Json<SocialActivity>, (StatusCode, Json<serde_json::Value>)> {
    let account = state
        .storage
        .get_account_by_id(&auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;

    let activity = SocialActivity {
        id: uuid::Uuid::new_v4().to_string(),
        account_id: account.id.clone(),
        username: account.username.clone(),
        display_name: account.display_name.clone(),
        avatar_url: account.profile.avatar_url.clone(),
        activity_type: payload.activity_type,
        title: payload.title,
        description: payload.description,
        game: payload.game,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    state
        .storage
        .record_social_activity(&activity)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(activity))
}
