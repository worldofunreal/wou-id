use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use wou_core::PlayerAccount;

use crate::state::AppState;

/// Backfill for accounts created before wallet derivation shipped.
/// Empty vault fields are re-derived deterministically with the same seed
/// the creation flows use, so healed addresses match what the account
/// would have received. Best-effort: a failed save still returns the
/// healed copy and the next read retries.
async fn ensure_embedded_wallets(state: &AppState, mut account: PlayerAccount) -> PlayerAccount {
    let w = &account.embedded_wallets;
    if !w.evm_address.is_empty()
        && !w.solana_address.is_empty()
        && !w.icp_principal.is_empty()
        && !w.bitcoin_address.is_empty()
    {
        return account;
    }
    let derived =
        wou_crypto::web3::derive_embedded_wallets(&account.id, "wou-sovereign-vault-secret-v1");
    let w = &mut account.embedded_wallets;
    if w.evm_address.is_empty() {
        w.evm_address = derived.evm_address;
    }
    if w.solana_address.is_empty() {
        w.solana_address = derived.solana_address;
    }
    if w.icp_principal.is_empty() {
        w.icp_principal = derived.icp_principal;
    }
    if w.bitcoin_address.is_empty() {
        w.bitcoin_address = derived.bitcoin_address;
    }
    account.updated_at = chrono::Utc::now().timestamp() as u64;
    if let Err(e) = state.storage.save_account(&account).await {
        tracing::warn!(account_id = %account.id, error = %e, "wallet backfill save failed");
    }
    account
}

// Hyper calls this on every start to validate the stored JWT.
pub async fn handle_me(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<PlayerAccount>, (StatusCode, Json<serde_json::Value>)> {
    match state.storage.get_account_by_id(&auth.account_id).await {
        Ok(Some(account)) => Ok(Json(ensure_embedded_wallets(&state, account).await)),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Account not found for session"})),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub status: &'static str,
    pub account: PlayerAccount,
    pub session_token: String,
}

// Remember-me: re-issue a fresh 30d JWT when the old one still verifies.
pub async fn handle_refresh(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<RefreshResponse>, (StatusCode, Json<serde_json::Value>)> {
    let account = ensure_embedded_wallets(
        &state,
        state
            .storage
            .get_account_by_id(&auth.account_id)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
            })?
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "Account not found for session"})),
                )
            })?,
    )
    .await;

    let token = state
        .jwt
        .issue_token(
            &account.id,
            &account.display_name,
            account.email.clone(),
            auth.claims.context,
            86400 * 30,
        )
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    Ok(Json(RefreshResponse {
        status: "authenticated",
        account,
        session_token: token,
    }))
}

// Stateless JWT: server has nothing to revoke yet (Valkey blocklist is a future step).
// Endpoint exists so clients share one logout path and we can add revoke without breaking them.
pub async fn handle_logout() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "logged_out"}))
}
