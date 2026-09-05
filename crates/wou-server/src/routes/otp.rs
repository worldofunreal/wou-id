use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::info;
use wou_core::{AuthProvider, GameContext, PendingOtp, PlayerAccount};
use wou_crypto::generate_secure_otp;

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
    Json(payload): Json<OtpRequestPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let clean_email = payload.email.trim().to_lowercase();

    // Basic email validation
    if !clean_email.contains('@') || !clean_email.contains('.') {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid email address format"})),
        ));
    }

    // Check rate limit (1 request per 60 seconds)
    if let Err(e) = state.storage.check_otp_rate_limit(&clean_email).await {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": e.to_string()})),
        ));
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

    info!("OTP request processed successfully for email {}", clean_email);

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
    Json(payload): Json<OtpVerifyPayload>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let clean_email = payload.email.trim().to_lowercase();
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

    let (final_account, is_new) = if let Some(mut existing_account) = existing_account_opt {
        // Case 1: Account already exists with this email -> Login / Restore
        existing_account.newsletter_opt_in = pending.newsletter_opt_in || existing_account.newsletter_opt_in;
        existing_account.updated_at = chrono::Utc::now().timestamp() as u64;
        state.storage.save_account(&existing_account).await.map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()})))
        })?;
        (existing_account, false)
    } else {
        // Case 2: New email link
        // If caller passed an active anonymous account_id, promote it!
        let target_id = payload
            .account_id
            .or(pending.account_id)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        let wallets = wou_crypto::web3::derive_embedded_wallets(&target_id, "wou-sovereign-vault-secret-v1");
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

    // Issue JWT session token
    let session_token = state
        .jwt
        .issue_token(
            &final_account.id,
            &final_account.display_name,
            final_account.email.clone(),
            payload.context,
            86400 * 30, // 30 days
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    info!(
        "OTP verification successful for account {} (email: {})",
        final_account.id, clean_email
    );

    Ok(Json(OtpVerifyResponse {
        status: "authenticated",
        account: final_account,
        session_token,
        is_new_account: is_new,
    }))
}
