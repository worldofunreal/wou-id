use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wou_core::{GameContext, QrChallenge};

use crate::state::AppState;

pub const QR_TTL_SECONDS: u64 = 300;
/// Post-approval delivery window: desktop polls every 2s.
pub const QR_DELIVERY_TTL_SECONDS: u64 = 60;

fn hash_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn hash_secret_hex(secret: &str) -> String {
    hex::encode(hash_secret(secret))
}

/// Constant-time equality: no early exit, no branch on content.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn check_secret(ch: &QrChallenge, secret: &str) -> bool {
    let Ok(stored) = hex::decode(&ch.secret_hash) else {
        return false;
    };
    let Ok(stored_arr) = <[u8; 32]>::try_from(stored) else {
        return false;
    };
    ct_eq(&stored_arr, &hash_secret(secret))
}

#[derive(Deserialize)]
pub struct QrStartPayload {
    #[serde(default)]
    pub context: GameContext,
    /// Returning user: push approval to linked bots when resolvable.
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Serialize)]
pub struct QrStartResponse {
    pub id: String,
    /// Fragment carries the secret: never leaves the browser (no server logs, no Referer).
    pub approve_url: String,
    pub secret: String,
    pub expires_in_seconds: u64,
    /// Bot channels that got a push ("telegram", "discord").
    pub notified: Vec<&'static str>,
}

#[derive(Deserialize)]
pub struct QrSecretPayload {
    pub secret: String,
}

/// Desktop: create a challenge and render `approve_url` as QR.
pub async fn handle_qr_start(
    State(state): State<AppState>,
    Json(payload): Json<QrStartPayload>,
) -> Result<Json<QrStartResponse>, (StatusCode, Json<serde_json::Value>)> {
    let id = uuid::Uuid::new_v4().to_string();
    let secret: String = rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
        .take(48)
        .map(char::from)
        .collect();

    let ch = QrChallenge {
        id: id.clone(),
        secret_hash: hash_secret_hex(&secret),
        context: payload.context,
        created_at: chrono::Utc::now().timestamp() as u64,
        approved_account_id: None,
        session_token: None,
    };
    state
        .storage
        .save_qr_challenge(&ch, QR_TTL_SECONDS)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    // Rate-limit pushable starts per username: usernames resolve to pushes,
    // so unbounded starts would be push-spam + a link-status oracle.
    // Plain anonymous QR (no username) has no push and stays unlimited.
    if let Some(un) = payload.username.as_deref().filter(|s| !s.trim().is_empty()) {
        if !state
            .storage
            .check_rate(&format!("wou_qr_start_rate:{}", un.to_lowercase()), 60)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        {
            return Err((StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error": "Wait a minute before a new code"}))));
        }
    }

    // Auto-push when the requester is resolvable and has bots linked.
    let mut notified = Vec::new();
    let mut account_opt: Option<wou_core::PlayerAccount> = None;
    if let Some(aid) = payload.account_id.as_deref().filter(|s| !s.is_empty()) {
        account_opt = state.storage.get_account_by_id(aid).await.unwrap_or(None);
    } else if let Some(un) = payload.username.as_deref().filter(|s| !s.is_empty()) {
        account_opt = state
            .storage
            .find_account_by_username(&un.trim().trim_start_matches('@').to_lowercase())
            .await
            .unwrap_or(None);
    }
    if let Some(account) = account_opt {
        if let Ok(chats) = state.storage.get_linked_chats("tg", &account.id).await {
            for chat in chats.into_iter().take(3) {
                if state.bots.telegram_qr_push(&chat, &id).await.is_ok() {
                    if !notified.contains(&"telegram") {
                        notified.push("telegram");
                    }
                }
            }
        }
        let mut dc_ids = state.storage.get_linked_chats("dc", &account.id).await.unwrap_or_default();
        for li in account.linked_identities.iter().filter(|i| i.provider == wou_core::AuthProvider::Discord) {
            if !dc_ids.contains(&li.external_id) {
                dc_ids.push(li.external_id.clone());
            }
        }
        for uid in dc_ids.into_iter().take(3) {
            if state.bots.discord_qr_push(&uid, &id).await.is_ok() {
                if !notified.contains(&"discord") {
                    notified.push("discord");
                }
            }
        }
    }

    Ok(Json(QrStartResponse {
        approve_url: format!("https://hyper.worldofunreal.com/approve.html#id={id}&secret={secret}"),
        id,
        secret,
        expires_in_seconds: QR_TTL_SECONDS,
        notified,
    }))
}

#[derive(Serialize)]
pub struct QrStatusResponse {
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<wou_core::PlayerAccount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

/// Desktop poll (secret required): pending → approved (single atomic delivery) → gone (410).
pub async fn handle_qr_status(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<QrSecretPayload>,
) -> Result<Json<QrStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ch) = state
        .storage
        .get_qr_challenge(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
    else {
        return Err((
            StatusCode::GONE,
            Json(serde_json::json!({"error": "QR challenge expired or unknown"})),
        ));
    };

    if !check_secret(&ch, &payload.secret) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid QR secret"})),
        ));
    }

    match (ch.approved_account_id.clone(), ch.session_token.clone()) {
        (Some(account_id), Some(token)) => {
            // Single atomic delivery.
            let account = state
                .storage
                .get_account_by_id(&account_id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
            let _ = state.storage.delete_qr_challenge(&id).await;
            Ok(Json(QrStatusResponse {
                status: "approved",
                account,
                session_token: Some(token),
            }))
        }
        _ => Ok(Json(QrStatusResponse {
            status: "pending",
            account: None,
            session_token: None,
        })),
    }
}

/// Phone (authed): approve the challenge. Desktop inherits your account.
pub async fn handle_qr_approve(
    auth: crate::AuthSession,
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<QrSecretPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let mut ch = state
        .storage
        .get_qr_challenge(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| {
            (
                StatusCode::GONE,
                Json(serde_json::json!({"error": "QR challenge expired or unknown"})),
            )
        })?;

    if !check_secret(&ch, &payload.secret) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid QR secret"})),
        ));
    }
    if ch.session_token.is_some() {
        return Err((
            StatusCode::GONE,
            Json(serde_json::json!({"error": "QR challenge already used"})),
        ));
    }

    let account = state
        .storage
        .get_account_by_id(&auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
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
            ch.context,
            86400 * 30,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    ch.approved_account_id = Some(account.id);
    ch.session_token = Some(token);
    // Short delivery window: no TTL extension past approval.
    state
        .storage
        .save_qr_challenge(&ch, QR_DELIVERY_TTL_SECONDS)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    Ok(Json(serde_json::json!({"status": "approved"})))
}

/// Desktop: cancel your own pending challenge (secret proves ownership).
pub async fn handle_qr_cancel(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<QrSecretPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ch) = state
        .storage
        .get_qr_challenge(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
    else {
        return Ok(Json(serde_json::json!({"status": "gone"})));
    };
    if !check_secret(&ch, &payload.secret) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid QR secret"})),
        ));
    }
    let _ = state.storage.delete_qr_challenge(&id).await;
    Ok(Json(serde_json::json!({"status": "cancelled"})))
}
