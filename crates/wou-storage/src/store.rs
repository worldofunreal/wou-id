use redb::{Database, ReadableTable, TableDefinition};
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::info;
use wou_core::{AuthProvider, PendingOtp, PlayerAccount, WouError};

const PLAYERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_players");
const IDENTITY_INDEX_TABLE: TableDefinition<&str, &str> = TableDefinition::new("wou_identity_index");
const NEWSLETTER_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_newsletter");
const INVENTORY_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_inventory");
const TRADES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_trades");

#[derive(Clone)]
pub struct WouStorage {
    redis_client: redis::Client,
    redb: Arc<Database>,
}

impl WouStorage {
    pub fn new(redis_url: &str, redb_path: &str) -> Result<Self, WouError> {
        let redis_client = redis::Client::open(redis_url)
            .map_err(|e| WouError::DatabaseError(format!("Failed to connect to Redis/Valkey: {e}")))?;

        // Ensure parent directory exists for Redb
        if let Some(parent) = std::path::Path::new(redb_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let redb = Database::create(redb_path)
            .map_err(|e| WouError::DatabaseError(format!("Failed to open Redb at {redb_path}: {e}")))?;

        // Initialize tables
        let write_txn = redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Failed to begin Redb init write txn: {e}")))?;
        {
            let _ = write_txn.open_table(PLAYERS_TABLE);
            let _ = write_txn.open_table(IDENTITY_INDEX_TABLE);
            let _ = write_txn.open_table(NEWSLETTER_TABLE);
            let _ = write_txn.open_table(INVENTORY_TABLE);
            let _ = write_txn.open_table(TRADES_TABLE);
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Failed to commit Redb init txn: {e}")))?;

        info!("WouStorage initialized successfully (Redis: {redis_url}, Redb: {redb_path})");

        Ok(Self {
            redis_client,
            redb: Arc::new(redb),
        })
    }

    async fn get_redis(&self) -> Result<redis::aio::MultiplexedConnection, WouError> {
        self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis connection failed: {e}")))
    }

    // =========================================================================
    // OTP & Rate Limiting (Hot State in Valkey)
    // =========================================================================

    pub async fn save_pending_otp(&self, otp: &PendingOtp, ttl_seconds: u64) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let key = format!("wou_otp:{}", otp.email.to_lowercase());
        let json = serde_json::to_string(otp)
            .map_err(|e| WouError::Internal(format!("OTP serialization error: {e}")))?;

        let _: () = conn
            .set_ex(&key, json, ttl_seconds)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SETEX failed: {e}")))?;

        // Set rate-limiting key (1 OTP request per 60 seconds per email)
        let rate_key = format!("wou_otp_rate:{}", otp.email.to_lowercase());
        let _: () = conn.set_ex(&rate_key, "1", 60).await.unwrap_or(());

        Ok(())
    }

    pub async fn check_otp_rate_limit(&self, email: &str) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let rate_key = format!("wou_otp_rate:{}", email.to_lowercase());
        let exists: bool = conn
            .exists(&rate_key)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis rate check failed: {e}")))?;

        if exists {
            let ttl: u64 = conn.ttl(&rate_key).await.unwrap_or(60);
            return Err(WouError::RateLimitExceeded(ttl));
        }

        Ok(())
    }

    pub async fn get_and_consume_otp(&self, email: &str, code: &str) -> Result<PendingOtp, WouError> {
        let mut conn = self.get_redis().await?;
        let key = format!("wou_otp:{}", email.to_lowercase());
        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis GET failed: {e}")))?;

        let Some(json_str) = json else {
            return Err(WouError::InvalidOrExpiredOtp);
        };

        let pending: PendingOtp = serde_json::from_str(&json_str)
            .map_err(|e| WouError::Internal(format!("OTP parse error: {e}")))?;

        if pending.code != code {
            return Err(WouError::InvalidOrExpiredOtp);
        }

        // Consume OTP (Delete from Redis)
        let _: () = conn.del(&key).await.unwrap_or(());

        Ok(pending)
    }

    pub async fn save_cache_string(&self, key: &str, val: &str, ttl_seconds: u64) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let _: () = conn
            .set_ex(key, val, ttl_seconds)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SETEX failed: {e}")))?;
        Ok(())
    }

    pub async fn get_cache_string(&self, key: &str) -> Result<Option<String>, WouError> {
        let mut conn = self.get_redis().await?;
        conn.get(key)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis GET failed: {e}")))
    }

    // =========================================================================
    // Durable Player Accounts & Indexing (Redb + Valkey Cache)
    // =========================================================================

    pub async fn save_account(&self, account: &PlayerAccount) -> Result<(), WouError> {
        let json_bytes = serde_json::to_vec(account)
            .map_err(|e| WouError::Internal(format!("Account serialization failed: {e}")))?;

        // 1. Write to Durable Redb
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut player_table = write_txn
                .open_table(PLAYERS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open players table failed: {e}")))?;
            player_table
                .insert(account.id.as_str(), json_bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert player failed: {e}")))?;

            let mut index_table = write_txn
                .open_table(IDENTITY_INDEX_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open index table failed: {e}")))?;

            // Index email
            if let Some(ref email) = account.email {
                let index_key = format!("email:{}", email.to_lowercase());
                index_table
                    .insert(index_key.as_str(), account.id.as_str())
                    .map_err(|e| WouError::DatabaseError(format!("Insert email index failed: {e}")))?;
            }

            // Index all linked identities
            for li in &account.linked_identities {
                let index_key = format!("{}:{}", li.provider.as_str(), li.external_id.to_lowercase());
                index_table
                    .insert(index_key.as_str(), account.id.as_str())
                    .map_err(|e| WouError::DatabaseError(format!("Insert identity index failed: {e}")))?;
            }
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;

        // 2. Update Hot Cache in Redis
        if let Ok(mut conn) = self.get_redis().await {
            let redis_key = format!("wou_player:{}", account.id);
            let _: Result<(), _> = conn.set_ex(&redis_key, serde_json::to_string(account).unwrap_or_default(), 86400).await;
        }

        Ok(())
    }

    pub async fn get_account_by_id(&self, account_id: &str) -> Result<Option<PlayerAccount>, WouError> {
        // Check Hot Cache
        if let Ok(mut conn) = self.get_redis().await {
            let redis_key = format!("wou_player:{}", account_id);
            if let Ok(Some(cached_json)) = conn.get::<_, Option<String>>(&redis_key).await {
                if let Ok(account) = serde_json::from_str::<PlayerAccount>(&cached_json) {
                    return Ok(Some(account));
                }
            }
        }

        // Read from Durable Redb
        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(PLAYERS_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open players table failed: {e}")))?;

        match table.get(account_id) {
            Ok(Some(value)) => {
                let account: PlayerAccount = serde_json::from_slice(value.value())
                    .map_err(|e| WouError::Internal(format!("Account deserialization failed: {e}")))?;
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(WouError::DatabaseError(format!("Redb get failed: {e}"))),
        }
    }

    pub async fn find_account_by_identity(
        &self,
        provider: &AuthProvider,
        external_id: &str,
    ) -> Result<Option<PlayerAccount>, WouError> {
        let index_key = format!("{}:{}", provider.as_str(), external_id.to_lowercase());

        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let index_table = read_txn
            .open_table(IDENTITY_INDEX_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open index table failed: {e}")))?;

        match index_table.get(index_key.as_str()) {
            Ok(Some(account_id_val)) => {
                let account_id = account_id_val.value();
                self.get_account_by_id(account_id).await
            }
            Ok(None) => Ok(None),
            Err(e) => Err(WouError::DatabaseError(format!("Redb index lookup failed: {e}"))),
        }
    }

    pub async fn find_account_by_email(&self, email: &str) -> Result<Option<PlayerAccount>, WouError> {
        self.find_account_by_identity(&AuthProvider::Email, email).await
    }

    // =========================================================================
    // Inventory — tradable digital collectibles (Redb, authoritative)
    // =========================================================================

    pub async fn get_inventory(&self, account_id: &str) -> Result<Vec<String>, WouError> {
        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(INVENTORY_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open inventory table failed: {e}")))?;
        match table.get(account_id) {
            Ok(Some(v)) => {
                let vec: Vec<String> = serde_json::from_slice(v.value())
                    .map_err(|e| WouError::Internal(format!("Inventory parse failed: {e}")))?;
                Ok(vec)
            }
            Ok(None) => Ok(vec![]),
            Err(e) => Err(WouError::DatabaseError(format!("Redb inventory get failed: {e}"))),
        }
    }

    pub async fn add_to_inventory(
        &self,
        account_id: &str,
        card_ids: Vec<String>,
    ) -> Result<Vec<String>, WouError> {
        let mut current = self.get_inventory(account_id).await?;
        let mut set: std::collections::HashSet<String> = current.drain(..).collect();
        for id in card_ids {
            let clean = id.trim().to_string();
            if !clean.is_empty() {
                set.insert(clean);
            }
        }
        let mut merged: Vec<String> = set.into_iter().collect();
        merged.sort();
        let bytes = serde_json::to_vec(&merged)
            .map_err(|e| WouError::Internal(format!("Inventory serialize failed: {e}")))?;
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut t = write_txn
                .open_table(INVENTORY_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open inventory table failed: {e}")))?;
            t.insert(account_id, bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert inventory failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;
        Ok(merged)
    }

    pub async fn remove_from_inventory(
        &self,
        account_id: &str,
        card_ids: Vec<String>,
    ) -> Result<Vec<String>, WouError> {
        let mut current = self.get_inventory(account_id).await?;
        let remove: std::collections::HashSet<String> = card_ids.into_iter().collect();
        current.retain(|id| !remove.contains(id));
        let bytes = serde_json::to_vec(&current)
            .map_err(|e| WouError::Internal(format!("Inventory serialize failed: {e}")))?;
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut t = write_txn
                .open_table(INVENTORY_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open inventory table failed: {e}")))?;
            t.insert(account_id, bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert inventory failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;
        Ok(current)
    }

    // Trades — simple offer ledger (card-for-card, atomic swap on accept)
    pub async fn save_trade(
        &self,
        trade_id: &str,
        json_bytes: &[u8],
    ) -> Result<(), WouError> {
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut t = write_txn
                .open_table(TRADES_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open trades table failed: {e}")))?;
            t.insert(trade_id, json_bytes)
                .map_err(|e| WouError::DatabaseError(format!("Insert trade failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;
        Ok(())
    }

    pub async fn get_trade(&self, trade_id: &str) -> Result<Option<Vec<u8>>, WouError> {
        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let t = read_txn
            .open_table(TRADES_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open trades table failed: {e}")))?;
        match t.get(trade_id) {
            Ok(Some(v)) => Ok(Some(v.value().to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(WouError::DatabaseError(format!("Redb trade get failed: {e}"))),
        }
    }

    pub async fn delete_trade(&self, trade_id: &str) -> Result<(), WouError> {
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut t = write_txn
                .open_table(TRADES_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open trades table failed: {e}")))?;
            t.remove(trade_id)
                .map_err(|e| WouError::DatabaseError(format!("Remove trade failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;
        Ok(())
    }

    pub async fn list_open_trades(&self, limit: usize) -> Result<Vec<Vec<u8>>, WouError> {
        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let t = read_txn
            .open_table(TRADES_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open trades table failed: {e}")))?;
        let mut out = Vec::new();
        for entry in t.iter().map_err(|e| WouError::DatabaseError(format!("Iter trades failed: {e}")))? {
            let (_, v) = entry.map_err(|e| WouError::DatabaseError(format!("Iter entry failed: {e}")))?;
            let bytes = v.value().to_vec();
            if let Ok(trade) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if trade.get("status").and_then(|s| s.as_str()) == Some("open") {
                    out.push(bytes);
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }
}
