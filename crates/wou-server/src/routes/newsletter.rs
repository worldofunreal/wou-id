use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::info;
use wou_core::GameContext;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct NewsletterSubscribePayload {
    pub email: String,
    #[serde(default)]
    pub context: GameContext,
}

#[derive(Deserialize)]
pub struct NewsletterUnsubscribePayload {
    pub email: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub token: Option<String>,
}

#[derive(Serialize)]
pub struct NewsletterResponse {
    pub status: &'static str,
    pub message: &'static str,
}

pub async fn handle_newsletter_subscribe(
    State(state): State<AppState>,
    Json(payload): Json<NewsletterSubscribePayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let clean_email = wou_core::canonical_email(&payload.email);
    if !clean_email.contains('@') || !clean_email.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid email format"})),
        ));
    }

    if let Ok(Some(mut account)) = state.storage.find_account_by_email(&clean_email).await {
        account.newsletter_opt_in = true;
        account.updated_at = chrono::Utc::now().timestamp() as u64;
        let _ = state.storage.save_account(&account).await;
    }

    info!("Subscribed {} to newsletter ({:?})", clean_email, payload.context);

    Ok(Json(NewsletterResponse {
        status: "subscribed",
        message: "Successfully subscribed to newsletter updates.",
    }))
}

pub async fn handle_newsletter_unsubscribe(
    State(state): State<AppState>,
    Json(payload): Json<NewsletterUnsubscribePayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let clean_email = wou_core::canonical_email(&payload.email);

    if let Ok(Some(mut account)) = state.storage.find_account_by_email(&clean_email).await {
        account.newsletter_opt_in = false;
        account.updated_at = chrono::Utc::now().timestamp() as u64;
        let _ = state.storage.save_account(&account).await;
    }

    info!("Unsubscribed {} from newsletter (One-Click)", clean_email);

    Ok(Json(NewsletterResponse {
        status: "unsubscribed",
        message: "You have been successfully removed from our mailing list.",
    }))
}
