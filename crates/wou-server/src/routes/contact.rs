use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{routes::guard::client_ip, state::AppState};

/// Default work: ~250k hashes, a second or two on a phone. Humans never notice
/// (it mines while they type); bots pay CPU for every single message.
const DEFAULT_DIFFICULTY_BITS: u32 = 18;
const CHALLENGE_TTL_SECS: u64 = 300;

#[derive(Deserialize)]
pub struct ContactPayload {
    pub name: String,
    pub email: String,
    pub message: String,
    /// Honeypot: real users leave it empty, bots fill it.
    #[serde(default)]
    pub website: String,
    /// Solved-work proof: id + counter such that
    /// sha256("{nonce}:{counter}") has `difficulty` leading zero bits.
    #[serde(default)]
    pub challenge_id: String,
    #[serde(default)]
    pub counter: u64,
}

#[derive(Serialize)]
pub struct ContactChallenge {
    pub id: String,
    pub nonce: String,
    pub difficulty: u32,
    pub expires_in_seconds: u64,
}

fn bad(msg: &'static str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg})))
}

fn difficulty(state: &AppState) -> u32 {
    state.contact_difficulty.clamp(8, 28)
}

fn meets_difficulty(hex: &str, bits: u32) -> bool {
    let bytes = match hex::decode(hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let full = (bits / 8) as usize;
    if bytes.len() < full + ((bits % 8 != 0) as usize) {
        return false;
    }
    if bytes[..full].iter().any(|&b| b != 0) {
        return false;
    }
    let rem = bits % 8;
    rem == 0 || bytes[full] >> (8 - rem) == 0
}

pub async fn handle_contact_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let ip = client_ip(&headers);
    if state.storage.protection_mode().await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Temporarily unavailable, try again later"})),
        ));
    }
    if state.storage.tally_ip(&ip).await.is_err() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many messages, try again later"})),
        ));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string().replace('-', "");
    let bits = difficulty(&state);
    state
        .storage
        .save_cache_string(
            &format!("wou_contact_ch:{id}"),
            &format!("{nonce}:{bits}"),
            CHALLENGE_TTL_SECS,
        )
        .await
        .map_err(|_| bad("Could not start, try again"))?;

    Ok(Json(ContactChallenge {
        id,
        nonce,
        difficulty: bits,
        expires_in_seconds: CHALLENGE_TTL_SECS,
    }))
}

pub async fn handle_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ContactPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let ip = client_ip(&headers);

    if state.storage.protection_mode().await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Temporarily unavailable, try again later"})),
        ));
    }

    // Honeypot: pretend success so bots learn nothing.
    if !payload.website.trim().is_empty() {
        warn!("contact honeypot hit from {ip}");
        return Ok(Json(serde_json::json!({"status": "received"})));
    }

    let name = payload.name.trim().replace(['<', '>'], "");
    let email = wou_core::canonical_email(&payload.email);
    let message = payload.message.trim().replace(['<', '>'], "");

    if name.is_empty() || name.len() > 100 {
        return Err(bad("Name must be 1-100 characters"));
    }
    if !email.contains('@') || !email.contains('.') || email.len() > 254 {
        return Err(bad("Invalid email format"));
    }
    if message.is_empty() || message.len() > 2000 {
        return Err(bad("Message must be 1-2000 characters"));
    }

    // Abuse gates: shared IP ceilings + 3 messages per hour per IP.
    if state.storage.tally_ip(&ip).await.is_err() {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many messages, try again later"})),
        ));
    }
    let hour = chrono::Utc::now().timestamp() / 3600;
    let mut slot_free = false;
    for slot in 0..3 {
        match state
            .storage
            .check_rate(&format!("wou_contact_hr:{ip}:{hour}:{slot}"), 3600)
            .await
        {
            Ok(true) => {
                slot_free = true;
                break;
            }
            _ => continue,
        }
    }
    if !slot_free {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many messages, try again in an hour"})),
        ));
    }

    // Solved-work proof: single hash check (cheap for us, CPU cost for bots).
    // Single-use + 5-minute expiry, same pattern as login nonces.
    let stored = state
        .storage
        .take_cache_string(&format!("wou_contact_ch:{}", payload.challenge_id))
        .await
        .map_err(|_| bad("Stale challenge, try again"))?
        .ok_or_else(|| bad("Stale challenge, try again"))?;
    let (nonce, bits) = stored.split_once(':').ok_or_else(|| bad("Stale challenge, try again"))?;
    let bits: u32 = bits.parse().unwrap_or(DEFAULT_DIFFICULTY_BITS);
    let mut hasher = Sha256::new();
    hasher.update(format!("{nonce}:{}", payload.counter).as_bytes());
    let hex = hex::encode(hasher.finalize());
    if !meets_difficulty(&hex, bits) {
        warn!("contact bad proof from {ip}");
        return Err(bad("Stale challenge, try again"));
    }

    let webhook = match state.contact_discord_webhook.clone().filter(|s| !s.is_empty()) {
        Some(url) => url,
        None => {
            tracing::error!("contact message dropped: WOU_CONTACT_DISCORD_WEBHOOK unset");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Temporarily unavailable, try again later"})),
            ));
        }
    };

    let content = format!(
        "**New inquiry**\n**Name:** {name}\n**Email:** {email}\n**Message:**\n{message}\n—\nIP: {ip} · {}",
        chrono::Utc::now().to_rfc3339()
    );
    reqwest::Client::new()
        .post(webhook)
        .json(&serde_json::json!({"content": content}))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("contact discord delivery failed: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "Could not deliver, try again"})),
            )
        })?;

    info!("contact inquiry from {ip} ({email})");
    Ok(Json(serde_json::json!({"status": "received"})))
}
