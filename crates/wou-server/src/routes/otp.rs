use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::info;
use wou_core::{canonical_email, AuthProvider, GameContext, PendingOtp, PlayerAccount, WouError, SESSION_TTL_SECONDS};
use wou_crypto::generate_secure_otp;

use crate::routes::guard::{client_ip, fire_admin_alert_once, log_tag, verified_owner};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct OtpRequestPayload {
    pub email: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub context: GameContext,
    #[serde(default = "default_opt_in")]
    pub newsletter_opt_in: bool,
}

fn default_opt_in() -> bool {
    false
}

#[derive(Serialize)]
pub struct OtpRequestResponse {
    pub status: &'static str,
    pub message: &'static str,
    pub expires_in_seconds: u64,
}

pub async fn handle_request_otp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OtpRequestPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let clean_email = canonical_email(&payload.email);

    // Basic email validation
    if !clean_email.contains('@') || !clean_email.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid email address format"})),
        ));
    }

    // Global protection mode (botnet response): pause new intake, keep sessions alive.
    if state.storage.protection_mode().await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Service in protection mode, try again later"})),
        ));
    }

    // Global spike detection (botnet signal; alert only, never block here).
    if let Ok(n) = state.storage.tally_global_minute().await {
        if n > 100 {
            let hour = chrono::Utc::now().timestamp() / 3600;
            fire_admin_alert_once(
                &state,
                &format!("spike:{hour}"),
                "OTP intake spike",
                format!("{n} OTP requests in the last minute"),
            )
            .await;
        }
    }

    // Per-IP gate (NAT-friendly ceilings; blocks alert once per day).
    let ip = client_ip(&headers);
    if let Err(e) = state.storage.tally_ip(&ip).await {
        fire_admin_alert_once(
            &state,
            &format!("ip:{ip}"),
            "IP blocked for OTP abuse",
            format!("ip={ip} error={e}"),
        )
        .await;
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }

    // Per-email abuse ladder (3/15min, >6/30min -> 24h, reoffense -> ban).
    if let Err(e) = state.storage.tally_otp_request(&clean_email).await {
        let tag = log_tag(&clean_email);
        let status = match &e {
            WouError::EmailBanned => {
                fire_admin_alert_once(
                    &state,
                    &format!("ban:{tag}"),
                    "Email banned for OTP abuse",
                    format!("tag={tag} error={e}"),
                )
                .await;
                StatusCode::FORBIDDEN
            }
            WouError::OtpPenalized(_) => {
                fire_admin_alert_once(
                    &state,
                    &format!("penalty:{tag}"),
                    "Email penalized 24h for OTP abuse",
                    format!("tag={tag} error={e}"),
                )
                .await;
                StatusCode::TOO_MANY_REQUESTS
            }
            _ => StatusCode::TOO_MANY_REQUESTS,
        };
        let mut body = serde_json::json!({"error": e.to_string()});
        match &e {
            WouError::OtpThrottled(s) | WouError::OtpPenalized(s) => {
                body["retry_after_seconds"] = (*s).into();
            }
            _ => {}
        }
        return Err((status, Json(body)));
    }

    // Generate 6-digit OTP
    let code = generate_secure_otp();
    let pending = PendingOtp {
        code: code.clone(),
        account_id: payload.account_id,
        email: clean_email.clone(),
        context: payload.context,
        newsletter_opt_in: payload.newsletter_opt_in,
        requested_at: chrono::Utc::now().timestamp() as u64,
    };

    // Save in Valkey with TTL (e.g. 10 minutes)
    state
        .storage
        .save_pending_otp(&pending, state.otp_expiry_seconds)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    // Dispatch branded email via Stalwart Mailer
    let expires_in_minutes = state.otp_expiry_seconds / 60;
    state
        .mailer
        .send_otp(&clean_email, payload.context, &code, expires_in_minutes)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    info!("OTP request ok tag={}", log_tag(&clean_email));

    Ok(Json(OtpRequestResponse {
        status: "success",
        message: "Verification code sent to your email.",
        expires_in_seconds: state.otp_expiry_seconds,
    }))
}

#[derive(Deserialize)]
pub struct OtpVerifyPayload {
    pub email: String,
    pub code: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub context: GameContext,
}

#[derive(Serialize)]
pub struct OtpVerifyResponse {
    pub status: &'static str,
    pub account: PlayerAccount,
    pub session_token: String,
    pub is_new_account: bool,
}

pub async fn handle_verify_otp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OtpVerifyPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let clean_email = canonical_email(&payload.email);
    let clean_code = payload.code.trim();

    // Consume and validate OTP from Valkey
    let pending = state
        .storage
        .get_and_consume_otp(&clean_email, clean_code)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": e.to_string()}))))?;

    // Check if an account already exists with this verified email
    let existing_account_opt = state
        .storage
        .find_account_by_email(&clean_email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let (mut final_account, is_new) = if let Some(mut existing_account) = existing_account_opt {
        // Case 1: Account already exists with this email -> Login / Restore.
        // Newsletter preference is NOT touched here: the request payload is
        // unauthenticated, so honoring it would let anyone flip opt-in on
        // someone else's account. Opt-in changes belong to authed profile edits.
        existing_account.updated_at = chrono::Utc::now().timestamp() as u64;
        state.storage.save_account(&existing_account).await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        })?;
        (existing_account, false)
    } else {
        // Case 2: New email link.
        // Promote the caller's own session account only (ownership proof via
        // Bearer, or the id minted at request time and echoed back). A verified
        // email must never adopt an arbitrary account id supplied by the client.
        let target_id = match payload.account_id.clone().or(pending.account_id.clone()) {
            Some(id)
                if state.storage.get_account_by_id(&id).await.ok().flatten().is_some()
                    && verified_owner(&headers, &state, &id).await =>
            {
                id
            }
            _ => uuid::Uuid::new_v4().to_string(),
        };

        let wallets = wou_crypto::web3::derive_embedded_wallets(&target_id, &state.vault_seed);
        let mut account = match state.storage.get_account_by_id(&target_id).await {
            Ok(Some(anon_acc)) => anon_acc,
            _ => {
                let user_prefix = clean_email.split('@').next().unwrap_or("commander");
                PlayerAccount::new_with_wallets(target_id, Some(user_prefix.to_string()), Some(user_prefix.to_string()), wallets)
            }
        };

        // Link verified email identity
        account.email = Some(clean_email.clone());
        account.newsletter_opt_in = pending.newsletter_opt_in;
        account.link_identity(AuthProvider::Email, clean_email.clone());
        account.updated_at = chrono::Utc::now().timestamp() as u64;

        state.storage.save_account(&account).await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        })?;

        (account, true)
    };

    // One-time welcome for a verified email on a new account.
    // Best-effort: welcome failure never fails auth; flag makes it idempotent.
    if is_new && !final_account.welcome_sent {
        if let Some(ref email) = final_account.email.clone() {
            final_account.welcome_sent = true;
            final_account.updated_at = chrono::Utc::now().timestamp() as u64;
            if state.storage.save_account(&final_account).await.is_ok() {
                let mailer = state.mailer.clone();
                let ctx = payload.context;
                let to = email.clone();
                let name = final_account.display_name.clone();
                tokio::spawn(async move {
                    let _ = mailer.send_welcome(&to, ctx, &name).await;
                });
            }
        }
    }

    // Issue JWT session token
    let session_token = state
        .jwt
        .issue_token(
            &final_account.id,
            &final_account.display_name,
            final_account.email.clone(),
            payload.context,
            SESSION_TTL_SECONDS,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    info!(
        "OTP verification successful for account {} (tag: {})",
        final_account.id,
        log_tag(&clean_email)
    );

    Ok(Json(OtpVerifyResponse {
        status: "authenticated",
        account: final_account,
        session_token,
        is_new_account: is_new,
    }))
}
