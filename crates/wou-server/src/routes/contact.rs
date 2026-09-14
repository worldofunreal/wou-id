use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{routes::guard::client_ip, state::AppState};

#[derive(Deserialize)]
pub struct ContactPayload {
    pub name: String,
    pub email: String,
    pub message: String,
    /// Honeypot: real users leave it empty, bots fill it.
    #[serde(default)]
    pub website: String,
    /// Invisible bot-check token (empty until site keys are configured).
    #[serde(default)]
    pub captcha_token: Option<String>,
}

fn bad(msg: &'static str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg})))
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

    // Invisible bot-check: enforced only once its secret is configured.
    let mut score_note = "off".to_string();
    if let Some(secret) = state.recaptcha_secret.clone().filter(|s| !s.is_empty()) {
        let token = payload.captcha_token.unwrap_or_default();
        if token.trim().is_empty() {
            return Err(bad("Bot verification required"));
        }
        let client = reqwest::Client::new();
        let res = client
            .post("https://www.google.com/recaptcha/api/siteverify")
            .form(&[("secret", secret.as_str()), ("response", token.trim())])
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| bad("Bot verification failed"))?;
        let body: serde_json::Value = res.json().await.map_err(|_| bad("Bot verification failed"))?;
        let ok = body.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        let score = body.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        score_note = format!("{score:.2}");
        if !ok || score < 0.5 {
            warn!("contact captcha rejected from {ip} (score {score:.2})");
            return Err(bad("Bot verification failed"));
        }
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
        "**New inquiry**\n**Name:** {name}\n**Email:** {email}\n**Message:**\n{message}\n—\nIP: {ip} · check: {score_note} · {}",
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
