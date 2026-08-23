use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct CollectPayload {
    pub card_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct InventoryResponse {
    pub account_id: String,
    pub card_ids: Vec<String>,
}

// Public: anyone can view an account's showcase inventory
pub async fn handle_get_inventory(
    Path(account_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<InventoryResponse>, (StatusCode, Json<serde_json::Value>)> {
    let exists = state
        .storage
        .get_account_by_id(&account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Account not found"}))));
    }
    let ids = state
        .storage
        .get_inventory(&account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(InventoryResponse { account_id, card_ids: ids }))
}

// Authenticated: caller must present valid AuthSession
pub async fn handle_collect(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<CollectPayload>,
) -> Result<Json<InventoryResponse>, (StatusCode, Json<serde_json::Value>)> {
    let account_id = auth.account_id;
    if payload.card_ids.is_empty() || payload.card_ids.len() > 50 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "card_ids must be 1..50"}))));
    }
    let ids = state
        .storage
        .add_to_inventory(&account_id, payload.card_ids)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(InventoryResponse { account_id, card_ids: ids }))
}

pub async fn handle_get_my_inventory(
    auth: crate::AuthSession,
    State(state): State<AppState>,
) -> Result<Json<InventoryResponse>, (StatusCode, Json<serde_json::Value>)> {
    let account_id = auth.account_id;
    let ids = state
        .storage
        .get_inventory(&account_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(InventoryResponse { account_id, card_ids: ids }))
}

// Trades — card-for-card, atomic
#[derive(Deserialize)]
pub struct TradeCreatePayload {
    pub offered: Vec<String>,
    pub requested: Vec<String>,
    pub to_account_id: Option<String>, // None = open offer
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TradeOffer {
    pub id: String,
    pub from_account: String,
    pub to_account: Option<String>,
    pub offered: Vec<String>,
    pub requested: Vec<String>,
    pub status: String, // open | accepted | cancelled
    pub created_at: u64,
}

pub async fn handle_trade_create(
    auth: crate::AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<TradeCreatePayload>,
) -> Result<Json<TradeOffer>, (StatusCode, Json<serde_json::Value>)> {
    let from = auth.account_id;

    if payload.offered.is_empty() || payload.requested.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "offered and requested must be non-empty"}))));
    }
    // Verify sender owns offered
    let inv = state.storage.get_inventory(&from).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    for c in &payload.offered {
        if !inv.contains(c) {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("You do not own {}", c)}))));
        }
    }

    let trade = TradeOffer {
        id: nanoid::nanoid!(12),
        from_account: from,
        to_account: payload.to_account_id,
        offered: payload.offered,
        requested: payload.requested,
        status: "open".to_string(),
        created_at: chrono::Utc::now().timestamp() as u64,
    };
    let bytes = serde_json::to_vec(&trade).unwrap();
    state.storage.save_trade(&trade.id, &bytes).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(trade))
}

pub async fn handle_trade_get(
    Path(trade_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<TradeOffer>, (StatusCode, Json<serde_json::Value>)> {
    let bytes = state.storage.get_trade(&trade_id).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let Some(b) = bytes else { return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Trade not found"})))) };
    let t: TradeOffer = serde_json::from_slice(&b).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(t))
}

pub async fn handle_trade_accept(
    auth: crate::AuthSession,
    Path(trade_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<TradeOffer>, (StatusCode, Json<serde_json::Value>)> {
    let acceptor = auth.account_id;

    let bytes = state.storage.get_trade(&trade_id).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let Some(b) = bytes else { return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Trade not found"})))) };
    let mut trade: TradeOffer = serde_json::from_slice(&b).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    if trade.status != "open" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Trade not open"}))));
    }
    if let Some(ref to) = trade.to_account {
        if to != &acceptor {
            return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Trade not addressed to you"}))));
        }
    }
    if trade.from_account == acceptor {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Cannot accept your own trade"}))));
    }
    // Verify acceptor owns requested
    let inv_acceptor = state.storage.get_inventory(&acceptor).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    for c in &trade.requested {
        if !inv_acceptor.contains(c) {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("Acceptor does not own {}", c)}))));
        }
    }
    // Verify offerer still owns offered (race check)
    let inv_offerer = state.storage.get_inventory(&trade.from_account).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    for c in &trade.offered {
        if !inv_offerer.contains(c) {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("Offerer no longer owns {}", c)}))));
        }
    }
    // Atomic swap
    state.storage.remove_from_inventory(&trade.from_account, trade.offered.clone()).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    state.storage.add_to_inventory(&acceptor, trade.offered.clone()).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    state.storage.remove_from_inventory(&acceptor, trade.requested.clone()).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    state.storage.add_to_inventory(&trade.from_account, trade.requested.clone()).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    trade.status = "accepted".to_string();
    let bytes = serde_json::to_vec(&trade).unwrap();
    state.storage.save_trade(&trade.id, &bytes).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(trade))
}

pub async fn handle_trade_cancel(
    auth: crate::AuthSession,
    Path(trade_id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let caller = auth.account_id;
    let bytes = state.storage.get_trade(&trade_id).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let Some(b) = bytes else { return Err((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Trade not found"})))) };
    let mut trade: TradeOffer = serde_json::from_slice(&b).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    if trade.from_account != caller {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Only offerer can cancel"}))));
    }
    trade.status = "cancelled".to_string();
    let bytes = serde_json::to_vec(&trade).unwrap();
    state.storage.save_trade(&trade.id, &bytes).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(serde_json::json!({"ok": true})))
}

pub async fn handle_trade_list(
    State(state): State<AppState>,
) -> Result<Json<Vec<TradeOffer>>, (StatusCode, Json<serde_json::Value>)> {
    let bytes_list = state.storage.list_open_trades(50).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let mut out = Vec::new();
    for b in bytes_list {
        if let Ok(t) = serde_json::from_slice::<TradeOffer>(&b) {
            out.push(t);
        }
    }
    Ok(Json(out))
}
