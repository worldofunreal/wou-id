use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use wou_core::{AssetInstance, AssetStatus, Collection, TokenType, WouError};

use crate::state::AppState;

fn map_err(e: WouError) -> (StatusCode, Json<serde_json::Value>) {
    let code = match &e {
        WouError::AssetNotFound(_) => StatusCode::NOT_FOUND,
        WouError::NotAssetOwner => StatusCode::FORBIDDEN,
        WouError::AssetFrozen(_) | WouError::SupplyExhausted(_) => StatusCode::CONFLICT,
        WouError::CollectionExists(_) | WouError::TokenExists(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, Json(serde_json::json!({"error": e.to_string()})))
}

/// Producer gate: closed set of account ids from `WOU_PRODUCER_IDS`.
/// Empty set = all producer routes fail closed. No roles table, no bloat.
fn require_producer(state: &AppState, auth: &crate::AuthSession) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.producer_ids.iter().any(|p| p == &auth.account_id) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Producer only"}))))
    }
}

#[derive(Deserialize)]
pub struct CreateCollectionPayload {
    pub id: String,
    pub name: String,
    pub symbol: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub tokens: Vec<TokenType>,
}

#[derive(Serialize)]
pub struct SeededCollection {
    pub collection: Collection,
    pub tokens: usize,
}

pub async fn handle_create_collection(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<CreateCollectionPayload>,
) -> Result<Json<SeededCollection>, (StatusCode, Json<serde_json::Value>)> {
    require_producer(&state, &auth)?;
    if payload.id.trim().is_empty() || payload.tokens.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "id and tokens required"}))));
    }
    let col = state
        .storage
        .create_collection(Collection {
            id: payload.id.trim().to_string(),
            name: payload.name,
            symbol: payload.symbol,
            description: payload.description,
            image: payload.image,
            created_at: 0,
        })
        .await
        .map_err(map_err)?;
    let mut n = 0;
    for mut tok in payload.tokens {
        tok.collection = col.id.clone();
        state.storage.register_token(tok).await.map_err(map_err)?;
        n += 1;
    }
    Ok(Json(SeededCollection { collection: col, tokens: n }))
}

pub async fn handle_list_collections(
    State(state): State<AppState>,
) -> Result<Json<Vec<Collection>>, (StatusCode, Json<serde_json::Value>)> {
    state.storage.list_collections().await.map_err(map_err).map(Json)
}

pub async fn handle_collection_tokens(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Vec<TokenType>>, (StatusCode, Json<serde_json::Value>)> {
    if state.storage.get_collection(&id).await.map_err(map_err)?.is_none() {
        return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Collection not found"}))));
    }
    state.storage.tokens_of_collection(&id).await.map_err(map_err).map(Json)
}

#[derive(Deserialize)]
pub struct ClaimPayload {
    pub token: String,
}

/// Free claim mints the next serial to the caller — capped by max_supply,
/// fails 409 when exhausted. This is the honest pack: real scarcity.
pub async fn handle_claim(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<ClaimPayload>,
) -> Result<Json<AssetInstance>, (StatusCode, Json<serde_json::Value>)> {
    let by = auth.account_id.clone();
    state.storage.claim_token(&payload.token, &auth.account_id, &by).await.map_err(map_err).map(Json)
}

#[derive(Deserialize)]
pub struct TransferPayload {
    pub to: String,
}

/// Owner-only gift/move. Frozen instances refuse.
pub async fn handle_transfer(
    auth: crate::AuthSession,
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<TransferPayload>,
) -> Result<Json<AssetInstance>, (StatusCode, Json<serde_json::Value>)> {
    if payload.to.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "to required"}))));
    }
    if state.storage.get_account_by_id(&payload.to).await.map_err(map_err)?.is_none() {
        return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Recipient not found"}))));
    }
    let by = auth.account_id.clone();
    state
        .storage
        .transfer_asset(&id, &auth.account_id, &payload.to, &by)
        .await
        .map_err(map_err)
        .map(Json)
}

pub async fn handle_freeze(
    auth: crate::AuthSession,
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<AssetInstance>, (StatusCode, Json<serde_json::Value>)> {
    require_producer(&state, &auth)?;
    let by = auth.account_id.clone();
    state.storage.set_asset_status(&id, AssetStatus::Frozen, &by).await.map_err(map_err).map(Json)
}

pub async fn handle_restore(
    auth: crate::AuthSession,
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<AssetInstance>, (StatusCode, Json<serde_json::Value>)> {
    require_producer(&state, &auth)?;
    let by = auth.account_id.clone();
    state.storage.set_asset_status(&id, AssetStatus::Active, &by).await.map_err(map_err).map(Json)
}

pub async fn handle_get_asset(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<AssetInstance>, (StatusCode, Json<serde_json::Value>)> {
    match state.storage.get_asset(&id).await.map_err(map_err)? {
        Some(a) => Ok(Json(a)),
        None => Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Asset not found"})))),
    }
}

pub async fn handle_owner_assets(
    Path(account): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Vec<AssetInstance>>, (StatusCode, Json<serde_json::Value>)> {
    state.storage.assets_of_owner(&account).await.map_err(map_err).map(Json)
}

pub async fn handle_asset_events(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<Vec<wou_core::AssetEvent>>, (StatusCode, Json<serde_json::Value>)> {
    state.storage.asset_events(&id).await.map_err(map_err).map(Json)
}

#[derive(Deserialize)]
pub struct FaucetPayload {
    pub to: String,
    pub amount: u64,
}

#[derive(Serialize)]
pub struct BalanceResponse {
    pub account: String,
    pub spiral: u64,
}

/// Producer-only demo faucet. Real deposits would credit here instead.
pub async fn handle_faucet(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<FaucetPayload>,
) -> Result<Json<BalanceResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_producer(&state, &auth)?;
    if state.storage.get_account_by_id(&payload.to).await.map_err(map_err)?.is_none() {
        return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Recipient not found"}))));
    }
    let spiral = state.storage.faucet_spiral(&payload.to, payload.amount).await.map_err(map_err)?;
    Ok(Json(BalanceResponse { account: payload.to, spiral }))
}

pub async fn handle_my_balance(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<BalanceResponse>, (StatusCode, Json<serde_json::Value>)> {
    let spiral = state.storage.spiral_balance(&auth.account_id).await.map_err(map_err)?;
    Ok(Json(BalanceResponse { account: auth.account_id, spiral }))
}

#[derive(Deserialize)]
pub struct CreateListingPayload {
    pub asset: String,
    pub price: u64,
}

/// Owner lists an Active instance at N SPIRAL. Instance reserves as Listed.
pub async fn handle_create_listing(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<CreateListingPayload>,
) -> Result<Json<wou_core::Listing>, (StatusCode, Json<serde_json::Value>)> {
    state
        .storage
        .create_listing(&payload.asset, &auth.account_id, payload.price)
        .await
        .map_err(map_err)
        .map(Json)
}

pub async fn handle_list_listings(
    State(state): State<AppState>,
) -> Result<Json<Vec<wou_core::Listing>>, (StatusCode, Json<serde_json::Value>)> {
    state.storage.list_open_listings(50).await.map_err(map_err).map(Json)
}

pub async fn handle_cancel_listing(
    auth: crate::AuthSession,
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<wou_core::Listing>, (StatusCode, Json<serde_json::Value>)> {
    state.storage.cancel_listing(&id, &auth.account_id).await.map_err(map_err).map(Json)
}

/// Atomic buy: SPIRAL + instance swap in one commit. Fails closed on
/// insufficient balance or concurrent sale.
pub async fn handle_buy_listing(
    auth: crate::AuthSession,
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<wou_core::Listing>, (StatusCode, Json<serde_json::Value>)> {
    match state.storage.buy_listing(&id, &auth.account_id).await {
        Ok(l) => Ok(Json(l)),
        Err(WouError::InsufficientBalance) => Err((StatusCode::PAYMENT_REQUIRED, Json(serde_json::json!({"error": "Insufficient SPIRAL balance"})))),
        Err(e) => Err(map_err(e)),
    }
}
