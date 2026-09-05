use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use wou_core::{AuthProvider, GameContext};

use crate::state::AppState;

fn link_code() -> String {
    rand::Rng::sample_iter(rand::thread_rng(), &rand::distributions::Alphanumeric)
        .take(8)
        .map(char::from)
        .collect::<String>()
        .to_uppercase()
}

/// Logged-in client: mint a one-time code to link a bot account.
pub async fn handle_link_start(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // One code per minute per account: codes are live Valkey keys.
    if !state
        .storage
        .check_rate(&format!("wou_link_rate:{}", auth.account_id), 60)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
    {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error": "Wait a minute before a new code"}))));
    }
    let code = link_code();
    state
        .storage
        .save_link_code(&code, &auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(serde_json::json!({ "code": code, "expires_in_seconds": 600 })))
}

#[derive(Serialize)]
pub struct LinkedResponse {
    pub telegram: bool,
    pub discord: bool,
    pub telegram_ids: Vec<String>,
    pub discord_ids: Vec<String>,
}

/// Which bot channels this account has linked (multi-link welcome).
pub async fn handle_linked(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<LinkedResponse>, (StatusCode, Json<serde_json::Value>)> {
    let tg = state
        .storage
        .get_linked_chats("tg", &auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let dc = state
        .storage
        .get_linked_chats("dc", &auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    // OAuth-linked Discord counts too: same user id namespace as the bot.
    let mut dc_ids = dc;
    let via_oauth_ids: Vec<String> = state
        .storage
        .get_account_by_id(&auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .map(|a| {
            a.linked_identities
                .iter()
                .filter(|i| i.provider == AuthProvider::Discord)
                .map(|i| i.external_id.clone())
                .collect()
        })
        .unwrap_or_default();
    for oid in via_oauth_ids {
        if !dc_ids.contains(&oid) {
            dc_ids.push(oid);
        }
    }
    Ok(Json(LinkedResponse {
        telegram: !tg.is_empty(),
        discord: !dc_ids.is_empty(),
        telegram_ids: tg,
        discord_ids: dc_ids,
    }))
}

#[derive(Deserialize)]
pub struct UnlinkPayload {
    pub external_id: String,
}

/// Remove one linked chat (account keeps everything else).
pub async fn handle_unlink(
    auth: crate::AuthSession,
    Path(ns): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<UnlinkPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if ns != "tg" && ns != "dc" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "ns must be tg or dc"}))));
    }
    // Only unlink your own link.
    let owner = state
        .storage
        .get_bot_link(&ns, &payload.external_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    if owner.as_deref() != Some(auth.account_id.as_str()) {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Not your link"}))));
    }
    state
        .storage
        .remove_bot_link(&ns, &payload.external_id, &auth.account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    if let Ok(Some(mut account)) = state.storage.get_account_by_id(&auth.account_id).await {
        let provider = if ns == "tg" {
            AuthProvider::Custom("telegram".into())
        } else {
            AuthProvider::Discord
        };
        account.linked_identities.retain(|i| !(i.provider == provider && i.external_id == payload.external_id));
        account.updated_at = chrono::Utc::now().timestamp() as u64;
        let _ = state.storage.save_account(&account).await;
        let _ = state.storage.remove_identity_index(provider.as_str(), &payload.external_id).await;
    }
    Ok(Json(serde_json::json!({"status": "unlinked"})))
}

/// Approve a QR challenge as `account_id` (shared by web + bot approvers).
/// Serialized per challenge so concurrent web+bot approvers cannot interleave.
async fn approve_challenge_for(
    state: &AppState,
    challenge_id: &str,
    account_id: &str,
    context: GameContext,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let err = |msg: &str| (StatusCode::GONE, Json(serde_json::json!({"error": msg})));
    if !state
        .storage
        .acquire_qr_lock(challenge_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
    {
        return Err(err("Approval already in progress"));
    }
    let res = approve_challenge_inner(state, challenge_id, account_id, context).await;
    let _ = state.storage.release_qr_lock(challenge_id).await;
    res
}

async fn approve_challenge_inner(
    state: &AppState,
    challenge_id: &str,
    account_id: &str,
    context: GameContext,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let err = |msg: &str| (StatusCode::GONE, Json(serde_json::json!({"error": msg})));
    let mut ch = state
        .storage
        .get_qr_challenge(challenge_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| err("QR challenge expired or unknown"))?;
    if ch.session_token.is_some() {
        return Err(err("QR challenge already used"));
    }
    let account = state
        .storage
        .get_account_by_id(account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?
        .ok_or_else(|| err("Account not found"))?;
    let token = state
        .jwt
        .issue_token(&account.id, &account.display_name, account.email.clone(), context, 86400 * 30)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    ch.approved_account_id = Some(account.id);
    ch.session_token = Some(token);
    state
        .storage
        .save_qr_challenge(&ch, crate::routes::qr::QR_DELIVERY_TTL_SECONDS)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(())
}

async fn link_bot_account(
    state: &AppState,
    ns: &str,
    external_id: &str,
    code: &str,
) -> Result<String, String> {
    // Brute-force brake: 10 tries per code per 10 minutes.
    let count_key = format!("wou_link_try:{}", code.trim().to_uppercase());
    let count: u64 = state
        .storage
        .get_cache_string(&count_key)
        .await
        .map_err(|e| e.to_string())?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if count >= 10 {
        return Err("Too many attempts. Get a fresh code from Hyper.".into());
    }
    let Some(account_id) = state
        .storage
        .consume_link_code(code.trim())
        .await
        .map_err(|e| e.to_string())?
    else {
        let _ = state.storage.save_cache_string(&count_key, &(count + 1).to_string(), 600).await;
        return Err("Unknown or expired code. Get a fresh one from Hyper.".into());
    };
    state
        .storage
        .save_bot_link(ns, external_id, &account_id)
        .await
        .map_err(|e| e.to_string())?;
    // Mirror into the account so every link is visible (link everything).
    if let Ok(Some(mut account)) = state.storage.get_account_by_id(&account_id).await {
        let provider = if ns == "tg" {
            AuthProvider::Custom("telegram".into())
        } else {
            AuthProvider::Discord
        };
        account.link_identity(provider, external_id.to_string());
        account.updated_at = chrono::Utc::now().timestamp() as u64;
        let _ = state.storage.save_account(&account).await;
    }
    Ok(account_id)
}

// ---------------------------------------------------------------------------
// Telegram webhook. Secret arrives in the X-Telegram-Bot-Api-Secret-Token
// header (set via setWebhook secret_token) — never in the query (proxies log it).
// ---------------------------------------------------------------------------

pub async fn handle_telegram_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(update): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let expected = std::env::var("TELEGRAM_WEBHOOK_SECRET").unwrap_or_default();
    let got = headers
        .get("x-telegram-bot-api-secret-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if expected.is_empty() || got != expected {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "bad webhook secret"}))));
    }

    // Button taps.
    if let Some(cb) = update.get("callback_query") {
        let chat_id = cb
            .pointer("/message/chat/id")
            .and_then(|v| v.as_i64())
            .map(|n| n.to_string())
            .unwrap_or_default();
        let data = cb.get("data").and_then(|v| v.as_str()).unwrap_or_default();
        let (action, challenge) = if let Some(c) = data.strip_prefix("qr:ok:") {
            ("ok", c)
        } else if let Some(c) = data.strip_prefix("qr:no:") {
            ("no", c)
        } else {
            ("", "")
        };
        if !chat_id.is_empty() && !challenge.is_empty() && (action == "ok" || action == "no") {
            // Private chats only: callback carrying a group id can never match a link.
            let private = update
                .pointer("/callback_query/message/chat/type")
                .and_then(|v| v.as_str())
                .unwrap_or("private")
                == "private";
            let toast = if !private {
                "Use a private chat."
            } else if action == "no" {
                let _ = state.storage.delete_qr_challenge(challenge).await;
                "Denied"
            } else {
                match state.storage.get_bot_link("tg", &chat_id).await {
                    Ok(Some(account_id)) => match state.storage.get_qr_challenge(challenge).await.unwrap_or(None) {
                        Some(ch) => match approve_challenge_for(&state, challenge, &account_id, ch.context).await {
                            Ok(()) => "Approved",
                            Err(_) => "Already used or expired",
                        },
                        None => "Already used or expired",
                    },
                    _ => "Chat not linked. Send /link CODE first.",
                }
            };
            if let Some(cb_id) = cb.get("id").and_then(|v| v.as_str()) {
                let _ = state.bots.answer_telegram_callback(cb_id, toast).await;
            }
        }
        return Ok(Json(serde_json::json!({"ok": true})));
    }

    // /link CODE in private chats only (never groups: any member could approve).
    if let Some(text) = update.pointer("/message/text").and_then(|v| v.as_str()) {
        let chat_id = update
            .pointer("/message/chat/id")
            .and_then(|v| v.as_i64())
            .map(|n| n.to_string())
            .unwrap_or_default();
        let chat_type = update
            .pointer("/message/chat/type")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if chat_id.is_empty() || chat_type != "private" {
            return Ok(Json(serde_json::json!({"ok": true})));
        }
        let code = text.trim().trim_start_matches("/link").trim().to_uppercase();
        let reply = if code.is_empty() {
            "Send /link YOURCODE from Hyper to connect this chat.".to_string()
        } else {
            match link_bot_account(&state, "tg", &chat_id, &code).await {
                Ok(_) => "Chat linked. Hyper will now offer push approval here.".to_string(),
                Err(e) => e,
            }
        };
        let _ = state.bots.telegram_text(&chat_id, &reply).await;
    }
    Ok(Json(serde_json::json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// Discord interactions endpoint (Ed25519-verified).
// ---------------------------------------------------------------------------

fn verify_discord_sig(public_key_hex: &str, timestamp: &str, body: &[u8], sig_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (Ok(pk), Ok(sig)) = (hex::decode(public_key_hex), hex::decode(sig_hex)) else {
        return false;
    };
    let (Ok(pk_arr), Ok(sig_arr)) = (<[u8; 32]>::try_from(pk), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&sig_arr) else {
        return false;
    };
    let mut msg = timestamp.as_bytes().to_vec();
    msg.extend_from_slice(body);
    key.verify(&msg, &signature).is_ok()
}

pub async fn handle_discord_interactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let public_key = std::env::var("DISCORD_PUBLIC_KEY").unwrap_or_default();
    let timestamp = headers
        .get("x-signature-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let sig = headers
        .get("x-signature-ed25519")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if public_key.is_empty() || !verify_discord_sig(&public_key, &timestamp, &body, &sig) {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "bad signature"}))));
    }
    let v: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "bad json"}))))?;

    // PING → PONG (Discord verifies the URL with this).
    if v.get("type").and_then(|t| t.as_u64()) == Some(1) {
        return Ok(Json(serde_json::json!({ "type": 1 })));
    }

    let user_id = v
        .pointer("/member/user/id")
        .or_else(|| v.pointer("/user/id"))
        .and_then(|u| u.as_str())
        .unwrap_or_default()
        .to_string();
    if user_id.is_empty() {
        return Ok(Json(serde_json::json!({ "type": 4, "data": { "content": "Unknown user.", "flags": 64 } })));
    }

    // Slash /link <code>.
    if v.get("type").and_then(|t| t.as_u64()) == Some(2) {
        let code = v
            .pointer("/data/options")
            .and_then(|o| o.as_array())
            .and_then(|a| a.iter().find(|o| o.get("name").and_then(|n| n.as_str()) == Some("code")))
            .and_then(|o| o.get("value").and_then(|x| x.as_str()))
            .unwrap_or("")
            .to_uppercase();
        // Auto-link when the Discord identity already exists via OAuth (same user id).
        let msg: String;
        if !code.is_empty() {
            match link_bot_account(&state, "dc", &user_id, &code).await {
                Ok(_) => msg = "Account linked. Hyper will now offer push approval here.".into(),
                Err(e) => msg = e,
            }
        } else if v.get("guild_id").is_none() {
            // Code-less match only in DMs: proves Discord ownership via signed
            // interaction AND matches the OAuth identity (same user id).
            if let Ok(Some(acc)) = state.storage.find_account_by_identity(&AuthProvider::Discord, &user_id).await {
                let _ = state.storage.save_bot_link("dc", &user_id, &acc.id).await;
                msg = "Account matched by your Discord login. Push approval on.".into();
            } else {
                msg = "Give me a code: Hyper → link Discord.".into();
            }
        } else {
            msg = "Give me a code: Hyper → link Discord (DMs only without a code).".into();
        }
        return Ok(Json(serde_json::json!({ "type": 4, "data": { "content": msg, "flags": 64 } })));
    }

    // Button taps (type 3).
    if v.get("type").and_then(|t| t.as_u64()) == Some(3) {
        let custom = v
            .pointer("/data/custom_id")
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        let (action, challenge) = if let Some(c) = custom.strip_prefix("qr:ok:") {
            ("ok", c)
        } else if let Some(c) = custom.strip_prefix("qr:no:") {
            ("no", c)
        } else {
            ("", "")
        };
        let text = if challenge.is_empty() {
            "Unknown button.".to_string()
        } else if action == "no" {
            let _ = state.storage.delete_qr_challenge(challenge).await;
            "Denied.".to_string()
        } else if let Ok(Some(account_id)) = state.storage.get_bot_link("dc", &user_id).await {
            match state.storage.get_qr_challenge(challenge).await.unwrap_or(None) {
                Some(ch) => match approve_challenge_for(&state, challenge, &account_id, ch.context).await {
                    Ok(()) => "Approved.".to_string(),
                    Err(_) => "Already used or expired.".to_string(),
                },
                None => "Already used or expired.".to_string(),
            }
        } else {
            "This Discord is not linked. Use /link CODE first.".to_string()
        };
        return Ok(Json(serde_json::json!({ "type": 4, "data": { "content": text, "flags": 64 } })));
    }

    Ok(Json(serde_json::json!({ "type": 4, "data": { "content": "?", "flags": 64 } })))
}
