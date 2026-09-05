use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use tracing::{error, info};
use wou_core::PlayerAccount;

use crate::state::AppState;

#[derive(Serialize)]
pub struct UploadResponse {
    pub status: &'static str,
    pub url: String,
    pub media_type: String,
    pub account: PlayerAccount,
}

pub async fn handle_upload_media(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let account_id = auth.account_id;

    let mut media_type = "avatar".to_string();
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_ext = "webp".to_string();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "media_type" {
            if let Ok(text) = field.text().await {
                // Closed enum: free text here becomes path traversal in the filename.
                media_type = if text.trim().to_lowercase() == "banner" {
                    "banner".to_string()
                } else {
                    "avatar".to_string()
                };
            }
        } else if name == "file" {
            if let Some(content_type) = field.content_type() {
                if content_type.contains("png") {
                    file_ext = "png".into();
                } else if content_type.contains("jpeg") || content_type.contains("jpg") {
                    file_ext = "jpg".into();
                } else {
                    file_ext = "webp".into();
                }
            }
            match field.bytes().await {
                Ok(bytes) => {
                    if bytes.len() > 2 * 1024 * 1024 {
                        return Err((
                            StatusCode::PAYLOAD_TOO_LARGE,
                            Json(serde_json::json!({"error": "File size exceeds 2MB limit"})),
                        ));
                    }
                    file_bytes = Some(bytes.to_vec());
                }
                Err(e) => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"error": format!("Failed to read file bytes: {e}")})),
                    ));
                }
            }
        }
    }

    let bytes = file_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Missing file field in multipart form"})),
        )
    })?;

    let upload_dir = std::env::var("WOU_UPLOAD_DIR").unwrap_or_else(|_| "/var/db/wou-id/uploads".into());
    if let Err(e) = tokio::fs::create_dir_all(&upload_dir).await {
        error!("Failed to create upload directory {}: {}", upload_dir, e);
    }

    let timestamp = chrono::Utc::now().timestamp();
    let file_name = format!("{}_{}_{}.{}", account_id, media_type, timestamp, file_ext);
    let full_path = std::path::Path::new(&upload_dir).join(&file_name);

    tokio::fs::write(&full_path, &bytes)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to save media: {e}")}))))?;

    let public_base = std::env::var("WOU_PUBLIC_UPLOAD_URL").unwrap_or_else(|_| "https://worldofunreal.com/uploads".into());
    let public_url = format!("{public_base}/{file_name}");

    let mut account = state
        .storage
        .get_account_by_id(&account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))))?;

    if media_type == "banner" {
        account.profile.banner_url = Some(public_url.clone());
    } else {
        account.profile.avatar_url = Some(public_url.clone());
    }
    account.updated_at = timestamp as u64;

    state
        .storage
        .save_account(&account)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    info!("Media uploaded successfully for account {}: {}", account_id, public_url);

    Ok(Json(UploadResponse {
        status: "ok",
        url: public_url,
        media_type,
        account,
    }))
}
