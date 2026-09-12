use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use wou_core::{AuthProvider, GameContext, PlayerAccount, SESSION_TTL_SECONDS};
use wou_crypto::web3::{verify_ethereum_signature, verify_solana_signature};

use crate::routes::guard::verified_owner;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct Web3ChallengeRequest {
    pub chain: String, // "solana" | "ethereum"
    pub public_address: String,
}

#[derive(Serialize)]
pub struct Web3ChallengeResponse {
    pub nonce: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct Web3VerifyRequest {
    pub chain: String, // "solana" | "ethereum"
    pub public_address: String,
    pub signature: String,
    pub message: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub context: GameContext,
}

#[derive(Serialize)]
pub struct Web3VerifyResponse {
    pub status: &'static str,
    pub account: PlayerAccount,
    pub session_token: String,
    pub is_new_account: bool,
}

pub async fn handle_web3_challenge(
    State(state): State<AppState>,
    Json(payload): Json<Web3ChallengeRequest>,
) -> Result<Json<Web3ChallengeResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Internet Identity is disabled server-side (see handle_web3_verify):
    // don't mint single-use nonces that could never verify.
    match payload.chain.to_lowercase().as_str() {
        "icp" | "internet_identity" | "id_ai" => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "Internet Identity login is temporarily disabled"})),
            ))
        }
        _ => {}
    }
    let nonce = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp();
    let message = format!(
        "Sign this message to authenticate with World of Unreal Identity Engine.\n\nAddress: {}\nNonce: {}\nTimestamp: {}",
        payload.public_address, nonce, timestamp
    );

    // Save nonce in Valkey with 5-minute expiry
    let key = format!("wou_web3_nonce:{}:{}", payload.chain.to_lowercase(), payload.public_address.to_lowercase());
    let _ = state.storage.save_cache_string(&key, &nonce, 300).await;

    Ok(Json(Web3ChallengeResponse { nonce, message }))
}

pub async fn handle_web3_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Web3VerifyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let chain = payload.chain.to_lowercase();
    let provider = match chain.as_str() {
        "solana" | "sol" => AuthProvider::Solana,
        "ethereum" | "evm" | "eth" => AuthProvider::Ethereum,
        "icp" | "internet_identity" | "id_ai" => AuthProvider::InternetIdentity,
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Unsupported Web3 chain: {chain}")})),
            ))
        }
    };

    // Internet Identity is disabled server-side: principal text is NOT proof of
    // ownership (no delegation verification yet). Format checks authenticate nobody.
    if provider == AuthProvider::InternetIdentity {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Internet Identity login is temporarily disabled"})),
        ));
    }

    // Enforce the challenge nonce: single-use, 5-minute window, bound to the message.
    // (Without this, any valid signature over any message would authenticate.)
    let nonce_key = format!(
        "wou_web3_nonce:{}:{}",
        chain,
        payload.public_address.to_lowercase()
    );
    match state.storage.take_cache_string(&nonce_key).await {
        Ok(Some(nonce)) if payload.message.contains(&nonce) => {}
        _ => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Challenge expired or already used"})),
            ))
        }
    }

    // Verify cryptographic signature.
    // (Internet Identity returns 503 above, so no arm is needed here.)
    let is_valid = match provider {
        AuthProvider::Solana => verify_solana_signature(&payload.public_address, &payload.message, &payload.signature),
        AuthProvider::Ethereum => verify_ethereum_signature(&payload.public_address, &payload.message, &payload.signature),
        _ => Ok(false),
    };

    match is_valid {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "Invalid cryptographic signature for wallet address."})),
            ))
        }
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Signature verification failed: {e}")})),
            ))
        }
    }

    // Check if account already exists with this linked wallet
    let existing_by_identity = state
        .storage
        .find_account_by_identity(&provider, &payload.public_address)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let (final_account, is_new) = if let Some(mut existing) = existing_by_identity {
        existing.updated_at = chrono::Utc::now().timestamp() as u64;
        let _ = state.storage.save_account(&existing).await;
        (existing, false)
    } else {
        // Merge into the caller's own session account only (ownership proof).
        // A valid signature for wallet W must never adopt arbitrary account V.
        let target_id = match payload.account_id.clone() {
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
            Ok(Some(anon)) => anon,
            _ => {
                PlayerAccount::new_with_wallets(target_id, None, None, wallets)
            }
        };

        account.link_identity(provider.clone(), payload.public_address.clone());
        state
            .storage
            .save_account(&account)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

        (account, true)
    };

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

    Ok(Json(Web3VerifyResponse {
        status: "authenticated",
        account: final_account,
        session_token,
        is_new_account: is_new,
    }))
}
