use redb::{Database, ReadableTable, TableDefinition};
use redis::AsyncCommands;
use std::sync::Arc;
use tracing::info;
use wou_core::{canonical_email, key_tag, AuthProvider, Clan, ClanMember, PendingOtp, PlayerAccount, PlayerSearchResult, WouError};

const PLAYERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_players");
const IDENTITY_INDEX_TABLE: TableDefinition<&str, &str> = TableDefinition::new("wou_identity_index");
const USERNAME_INDEX_TABLE: TableDefinition<&str, &str> = TableDefinition::new("wou_username_index");
const NEWSLETTER_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_newsletter");
const INVENTORY_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_inventory");
const TRADES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_trades");
const FOLLOWERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_social_followers");
const ACTIVITY_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_social_activity");
const CLANS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_clans");
const CLAN_MEMBERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("wou_clan_members");

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
            let _ = write_txn.open_table(USERNAME_INDEX_TABLE);
            let _ = write_txn.open_table(NEWSLETTER_TABLE);
            let _ = write_txn.open_table(INVENTORY_TABLE);
            let _ = write_txn.open_table(TRADES_TABLE);
            let _ = write_txn.open_table(FOLLOWERS_TABLE);
            let _ = write_txn.open_table(ACTIVITY_TABLE);
            let _ = write_txn.open_table(CLANS_TABLE);
            let _ = write_txn.open_table(CLAN_MEMBERS_TABLE);
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
        let key = format!("wou_otp:{}", key_tag(&canonical_email(&otp.email)));
        let json = serde_json::to_string(otp)
            .map_err(|e| WouError::Internal(format!("OTP serialization error: {e}")))?;

        let _: () = conn
            .set_ex(&key, json, ttl_seconds)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SETEX failed: {e}")))?;

        Ok(())
    }

    // OTP abuse ladder (all counters are best-effort Valkey TTLs, ~0.1ms each):
    // 3 requests / 15 min per email, >6 / 30 min -> 24h penalty,
    // any request during penalty -> 90d ban. 5 wrong guesses burn the code.
    pub const OTP_REQ_MAX: u64 = 3;
    pub const OTP_REQ_WINDOW_SECS: u64 = 900;
    pub const OTP_ABUSE_MAX: u64 = 6;
    pub const OTP_ABUSE_WINDOW_SECS: u64 = 1800;
    pub const OTP_PENALTY_SECS: u64 = 86400;
    pub const OTP_BAN_SECS: u64 = 90 * 86400;
    pub const OTP_GUESS_MAX: u64 = 5;
    // NAT-friendly per-IP limits (schools/offices share IPs; botnets don't).
    pub const IP_REQ_HR_MAX: u64 = 100;
    pub const IP_REQ_HR_WINDOW_SECS: u64 = 3600;
    pub const IP_REQ_DAY_MAX: u64 = 300;
    pub const IP_REQ_DAY_WINDOW_SECS: u64 = 86400;
    /// Global protection mode flag: presence of this key pauses new OTP/anonymous intake.
    /// Toggled live with `valkey-cli SET wou_protect_mode 1` / `DEL wou_protect_mode`.
    pub const PROTECT_MODE_KEY: &str = "wou_protect_mode";

    async fn incr_win(&self, key: &str, window_secs: u64) -> Result<u64, WouError> {
        let mut conn = self.get_redis().await?;
        let n: u64 = conn
            .incr(key, 1)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis INCR failed: {e}")))?;
        if n == 1 {
            let _: () = conn.expire(key, window_secs as i64).await.unwrap_or(());
        }
        Ok(n)
    }

    async fn ttl_of(&self, key: &str) -> u64 {
        match self.get_redis().await {
            Ok(mut conn) => conn.ttl(key).await.unwrap_or(60).max(1) as u64,
            Err(_) => 60,
        }
    }

    /// Gate an OTP request through the abuse ladder. Counts the attempt.
    pub async fn tally_otp_request(&self, email: &str) -> Result<(), WouError> {
        let t = key_tag(&canonical_email(email));
        let mut conn = self.get_redis().await?;
        let ban_key = format!("wou_otp_ban:{t}");
        let ban: bool = conn.exists(&ban_key).await.unwrap_or(false);
        if ban {
            return Err(WouError::EmailBanned);
        }
        let pen_key = format!("wou_otp_penalty:{t}");
        let penalized: bool = conn.exists(&pen_key).await.unwrap_or(false);
        if penalized {
            // Reoffense during penalty -> ban.
            let _: () = conn
                .set_ex(&ban_key, "1", Self::OTP_BAN_SECS)
                .await
                .unwrap_or(());
            return Err(WouError::EmailBanned);
        }
        drop(conn);

        let abuse = self
            .incr_win(&format!("wou_otp_abuse:{t}"), Self::OTP_ABUSE_WINDOW_SECS)
            .await?;
        if abuse > Self::OTP_ABUSE_MAX {
            let mut conn = self.get_redis().await?;
            let _: () = conn
                .set_ex(&pen_key, "1", Self::OTP_PENALTY_SECS)
                .await
                .unwrap_or(());
            return Err(WouError::OtpPenalized(Self::OTP_PENALTY_SECS as u64));
        }

        let win_key = format!("wou_otp_window:{t}");
        let n = self.incr_win(&win_key, Self::OTP_REQ_WINDOW_SECS).await?;
        if n > Self::OTP_REQ_MAX {
            return Err(WouError::OtpThrottled(self.ttl_of(&win_key).await));
        }
        Ok(())
    }

    /// Gate intake by client IP (NAT-friendly ceilings).
    pub async fn tally_ip(&self, ip: &str) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let block_key = format!("wou_ip_block:{ip}");
        let blocked: bool = conn.exists(&block_key).await.unwrap_or(false);
        if blocked {
            return Err(WouError::IpBlocked);
        }
        drop(conn);
        let hr = self
            .incr_win(&format!("wou_ip_hr:{ip}"), Self::IP_REQ_HR_WINDOW_SECS)
            .await?;
        let day = self
            .incr_win(&format!("wou_ip_day:{ip}"), Self::IP_REQ_DAY_WINDOW_SECS)
            .await?;
        if hr > Self::IP_REQ_HR_MAX || day > Self::IP_REQ_DAY_MAX {
            if let Ok(mut conn) = self.get_redis().await {
                let _: () = conn
                    .set_ex(&block_key, "1", Self::OTP_PENALTY_SECS)
                    .await
                    .unwrap_or(());
            }
            return Err(WouError::IpBlocked);
        }
        Ok(())
    }

    /// True while the instance is in manual protection mode (botnet response).
    pub async fn protection_mode(&self) -> bool {
        match self.get_redis().await {
            Ok(mut conn) => conn.exists(Self::PROTECT_MODE_KEY).await.unwrap_or(false),
            Err(_) => false,
        }
    }

    /// GET+DEL a short-lived cache string (web3 nonces: single-use).
    pub async fn take_cache_string(&self, key: &str) -> Result<Option<String>, WouError> {
        let mut conn = self.get_redis().await?;
        let val: Option<String> = conn
            .get(key)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis GET failed: {e}")))?;
        if val.is_some() {
            let _: () = conn.del(key).await.unwrap_or(());
        }
        Ok(val)
    }

    /// Global OTP intake per minute (spike detection for the circuit breaker).
    pub async fn tally_global_minute(&self) -> Result<u64, WouError> {
        self.incr_win("wou_otp_global_min", 90).await
    }

    /// Toggle protection mode programmatically (ops use valkey-cli; tests use this).
    pub async fn set_protection_mode(&self, on: bool) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        if on {
            let _: () = conn
                .set(Self::PROTECT_MODE_KEY, "1")
                .await
                .map_err(|e| WouError::DatabaseError(format!("Redis SET failed: {e}")))?;
        } else {
            let _: () = conn
                .del(Self::PROTECT_MODE_KEY)
                .await
                .map_err(|e| WouError::DatabaseError(format!("Redis DEL failed: {e}")))?;
        }
        Ok(())
    }

    pub async fn get_and_consume_otp(&self, email: &str, code: &str) -> Result<PendingOtp, WouError> {
        let mut conn = self.get_redis().await?;
        let t = key_tag(&canonical_email(email));
        let key = format!("wou_otp:{t}");
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
            // Wrong guess: count it, feed the same abuse ladder (organic link),
            // and burn the code after OTP_GUESS_MAX failures.
            let fail_key = format!("wou_otp_fail:{t}");
            let fails = self.incr_win(&fail_key, 600).await.unwrap_or(1);
            let _ = self
                .incr_win(&format!("wou_otp_abuse:{t}"), Self::OTP_ABUSE_WINDOW_SECS)
                .await;
            if fails >= Self::OTP_GUESS_MAX {
                let _: () = conn.del(&key).await.unwrap_or(());
                let _: () = conn.del(&fail_key).await.unwrap_or(());
            }
            return Err(WouError::InvalidOrExpiredOtp);
        }

        // Consume OTP (Delete from Redis) + reset guess counter.
        let _: () = conn.del(&key).await.unwrap_or(());
        let _: () = conn
            .del(format!("wou_otp_fail:{t}"))
            .await
            .unwrap_or(());

        Ok(pending)
    }

    // =========================================================================
    // Bot links + link codes (Valkey; links persistent, codes 10-min TTL)
    // =========================================================================

    /// One-time link code shown by a logged-in client: `wou_link:{code}` → account_id.
    pub async fn save_link_code(&self, code: &str, account_id: &str) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let _: () = conn
            .set_ex(format!("wou_link:{code}"), account_id, 600)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SETEX failed: {e}")))?;
        Ok(())
    }

    /// Atomic GET+DEL: one-time codes can never double-spend, even concurrently.
    pub async fn consume_link_code(&self, code: &str) -> Result<Option<String>, WouError> {
        let mut conn = self.get_redis().await?;
        let key = format!("wou_link:{}", code.to_uppercase());
        let script = redis::Script::new(
            "local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); end; return v",
        );
        script
            .key(&key)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis consume failed: {e}")))
    }

    /// Best-effort fixed-window gate: true when this is the first hit in `ttl_seconds`.
    pub async fn check_rate(&self, key: &str, ttl_seconds: u64) -> Result<bool, WouError> {
        let mut conn = self.get_redis().await?;
        let fresh: bool = conn
            .set_nx(key, "1")
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SETNX failed: {e}")))?;
        if fresh {
            let _: () = conn.expire(key, ttl_seconds as i64).await.unwrap_or(());
        }
        Ok(fresh)
    }

    /// Short mutex around QR approval so web+bot approvers serialize (5s).
    pub async fn acquire_qr_lock(&self, id: &str) -> Result<bool, WouError> {
        let mut conn = self.get_redis().await?;
        let fresh: bool = conn
            .set_nx(format!("wou_qr_lock:{id}"), "1")
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SETNX failed: {e}")))?;
        if fresh {
            let _: () = conn.expire(format!("wou_qr_lock:{id}"), 5).await.unwrap_or(());
        }
        Ok(fresh)
    }

    pub async fn release_qr_lock(&self, id: &str) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let _: () = conn.del(format!("wou_qr_lock:{id}")).await.unwrap_or(());
        Ok(())
    }

    /// Delete one identity-index row (unlink must not leave ghost login mappings).
    pub async fn remove_identity_index(&self, provider: &str, external_id: &str) -> Result<(), WouError> {
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut index_table = write_txn
                .open_table(IDENTITY_INDEX_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open index table failed: {e}")))?;
            let index_key = format!("{}:{}", provider, external_id.to_lowercase());
            index_table
                .remove(index_key.as_str())
                .map_err(|e| WouError::DatabaseError(format!("Remove identity index failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;
        Ok(())
    }

    /// chat/user id → account id, e.g. `wou_tg_link:123` or `wou_dc_link:456`.
    pub async fn save_bot_link(&self, ns: &str, external_id: &str, account_id: &str) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let _: () = conn
            .set(format!("wou_{ns}_link:{external_id}"), account_id)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SET failed: {e}")))?;
        let _: () = conn
            .sadd(format!("wou_{ns}_accounts:{account_id}"), external_id)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SADD failed: {e}")))?;
        Ok(())
    }

    pub async fn get_bot_link(&self, ns: &str, external_id: &str) -> Result<Option<String>, WouError> {
        let mut conn = self.get_redis().await?;
        conn.get(format!("wou_{ns}_link:{external_id}"))
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis GET failed: {e}")))
    }

    pub async fn get_linked_chats(&self, ns: &str, account_id: &str) -> Result<Vec<String>, WouError> {
        let mut conn = self.get_redis().await?;
        conn.smembers(format!("wou_{ns}_accounts:{account_id}"))
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SMEMBERS failed: {e}")))
    }

    pub async fn remove_bot_link(&self, ns: &str, external_id: &str, account_id: &str) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let _: () = conn.del(format!("wou_{ns}_link:{external_id}")).await.unwrap_or(());
        let _: () = conn
            .srem(format!("wou_{ns}_accounts:{account_id}"), external_id)
            .await
            .unwrap_or(());
        Ok(())
    }

    // =========================================================================
    // QR login challenges (Valkey-only, 5-minute TTL, single-use)
    // =========================================================================

    pub async fn save_qr_challenge(&self, ch: &wou_core::QrChallenge, ttl_seconds: u64) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let key = format!("wou_qr:{}", ch.id);
        let json = serde_json::to_string(ch)
            .map_err(|e| WouError::Internal(format!("QR serialization error: {e}")))?;
        let _: () = conn
            .set_ex(&key, json, ttl_seconds)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis SETEX failed: {e}")))?;
        Ok(())
    }

    pub async fn get_qr_challenge(&self, id: &str) -> Result<Option<wou_core::QrChallenge>, WouError> {
        let mut conn = self.get_redis().await?;
        let key = format!("wou_qr:{id}");
        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| WouError::DatabaseError(format!("Redis GET failed: {e}")))?;
        match json {
            None => Ok(None),
            Some(s) => serde_json::from_str(&s)
                .map(Some)
                .map_err(|e| WouError::Internal(format!("QR parse error: {e}"))),
        }
    }

    pub async fn delete_qr_challenge(&self, id: &str) -> Result<(), WouError> {
        let mut conn = self.get_redis().await?;
        let key = format!("wou_qr:{id}");
        let _: () = conn.del(&key).await.unwrap_or(());
        Ok(())
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

            let mut user_index_table = write_txn
                .open_table(USERNAME_INDEX_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open username index table failed: {e}")))?;

            // Index unique handle @username
            if !account.username.is_empty() {
                let user_key = account.username.to_lowercase();
                user_index_table
                    .insert(user_key.as_str(), account.id.as_str())
                    .map_err(|e| WouError::DatabaseError(format!("Insert username index failed: {e}")))?;
            }

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
            let user_key = format!("wou_user_idx:{}", account.username.to_lowercase());
            let _: Result<(), _> = conn.set_ex(&user_key, &account.id, 86400).await;
        }

        Ok(())
    }

    pub async fn get_account_by_id(&self, account_id: &str) -> Result<Option<PlayerAccount>, WouError> {
        // Check Hot Cache
        if let Ok(mut conn) = self.get_redis().await {
            let redis_key = format!("wou_player:{}", account_id);
            if let Ok(Some(cached_json)) = conn.get::<_, Option<String>>(&redis_key).await {
                if let Ok(mut account) = serde_json::from_str::<PlayerAccount>(&cached_json) {
                    let mut modified = false;
                    if account.username.is_empty() {
                        let (gen_user, gen_name, gen_profile) = wou_core::generate_noble_animal_identity(&account.id, if account.display_name.is_empty() { None } else { Some(account.display_name.clone()) });
                        account.username = gen_user;
                        if account.display_name.is_empty() {
                            account.display_name = gen_name;
                        }
                        if account.profile.custom_attributes.is_empty() {
                            account.profile = gen_profile;
                        }
                        modified = true;
                    }
                    if modified {
                        let _ = self.save_account(&account).await;
                    }
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
                let mut account: PlayerAccount = serde_json::from_slice(value.value())
                    .map_err(|e| WouError::Internal(format!("Account deserialization failed: {e}")))?;
                let mut modified = false;
                if account.username.is_empty() {
                    let (gen_user, gen_name, gen_profile) = wou_core::generate_noble_animal_identity(&account.id, if account.display_name.is_empty() { None } else { Some(account.display_name.clone()) });
                    account.username = gen_user;
                    if account.display_name.is_empty() {
                        account.display_name = gen_name;
                    }
                    if account.profile.custom_attributes.is_empty() {
                        account.profile = gen_profile;
                    }
                    modified = true;
                }
                if modified {
                    let _ = self.save_account(&account).await;
                }
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(WouError::DatabaseError(format!("Redb get failed: {e}"))),
        }
    }

    pub async fn find_account_by_username(&self, username: &str) -> Result<Option<PlayerAccount>, WouError> {
        let clean_user = username.trim().trim_start_matches('@').to_lowercase();

        // Check cache
        if let Ok(mut conn) = self.get_redis().await {
            let user_key = format!("wou_user_idx:{}", clean_user);
            if let Ok(Some(account_id)) = conn.get::<_, Option<String>>(&user_key).await {
                return self.get_account_by_id(&account_id).await;
            }
        }

        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let index_table = read_txn
            .open_table(USERNAME_INDEX_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open username index failed: {e}")))?;

        match index_table.get(clean_user.as_str()) {
            Ok(Some(account_id_val)) => {
                let account_id = account_id_val.value();
                self.get_account_by_id(account_id).await
            }
            Ok(None) => Ok(None),
            Err(e) => Err(WouError::DatabaseError(format!("Username lookup failed: {e}"))),
        }
    }

    pub async fn is_username_available(&self, username: &str, current_account_id: &str) -> Result<bool, WouError> {
        let clean_user = username.trim().trim_start_matches('@').to_lowercase();
        if clean_user.len() < 3 || clean_user.len() > 24 {
            return Ok(false);
        }
        // Must be alphanumeric + underscores
        if !clean_user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Ok(false);
        }

        match self.find_account_by_username(&clean_user).await? {
            Some(existing) => Ok(existing.id == current_account_id),
            None => Ok(true),
        }
    }

    pub async fn record_social_activity(&self, activity: &wou_core::SocialActivity) -> Result<(), WouError> {
        let json_bytes = serde_json::to_vec(activity)
            .map_err(|e| WouError::Internal(format!("Activity serialize failed: {e}")))?;

        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb txn failed: {e}")))?;
        {
            let mut table = write_txn
                .open_table(ACTIVITY_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open activity table failed: {e}")))?;
            table
                .insert(activity.id.as_str(), json_bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert activity failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;

        // Push to Redis Activity Stream
        if let Ok(mut conn) = self.get_redis().await {
            let _: Result<(), _> = conn.lpush("wou_global_activity_feed", serde_json::to_string(activity).unwrap_or_default()).await;
            let _: Result<(), _> = conn.ltrim("wou_global_activity_feed", 0, 99).await;
        }

        Ok(())
    }

    pub async fn get_social_feed(&self, limit: usize) -> Result<Vec<wou_core::SocialActivity>, WouError> {
        if let Ok(mut conn) = self.get_redis().await {
            if let Ok(items) = conn.lrange::<_, Vec<String>>("wou_global_activity_feed", 0, (limit.saturating_sub(1)) as isize).await {
                let parsed: Vec<wou_core::SocialActivity> = items
                    .into_iter()
                    .filter_map(|s| serde_json::from_str(&s).ok())
                    .collect();
                if !parsed.is_empty() {
                    return Ok(parsed);
                }
            }
        }

        // Fallback to durable storage
        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(ACTIVITY_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open activity table failed: {e}")))?;

        let mut activities = Vec::new();
        let mut count = 0;
        for item in table.iter().map_err(|e| WouError::DatabaseError(e.to_string()))? {
            if count >= limit { break; }
            if let Ok((_, val)) = item {
                if let Ok(act) = serde_json::from_slice::<wou_core::SocialActivity>(val.value()) {
                    activities.push(act);
                    count += 1;
                }
            }
        }
        activities.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(activities)
    }

    pub async fn follow_user(&self, follower_id: &str, target_id: &str) -> Result<(), WouError> {
        if follower_id == target_id { return Ok(()); }

        let edge_key = format!("follow:{follower_id}:{target_id}");
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb txn failed: {e}")))?;
        {
            let mut table = write_txn
                .open_table(FOLLOWERS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open followers table failed: {e}")))?;
            table
                .insert(edge_key.as_str(), b"1".as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert follower failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;

        if let Ok(mut conn) = self.get_redis().await {
            let f_key = format!("wou_following:{}", follower_id);
            let t_key = format!("wou_followers:{}", target_id);
            let _: Result<(), _> = conn.sadd(f_key, target_id).await;
            let _: Result<(), _> = conn.sadd(t_key, follower_id).await;
        }

        // Update follower/following counts on accounts
        if let Some(mut follower) = self.get_account_by_id(follower_id).await? {
            follower.following_count = follower.following_count.saturating_add(1);
            let _ = self.save_account(&follower).await;
        }
        if let Some(mut target) = self.get_account_by_id(target_id).await? {
            target.followers_count = target.followers_count.saturating_add(1);
            let _ = self.save_account(&target).await;
        }

        Ok(())
    }

    pub async fn unfollow_user(&self, follower_id: &str, target_id: &str) -> Result<(), WouError> {
        if follower_id == target_id { return Ok(()); }

        let edge_key = format!("follow:{follower_id}:{target_id}");
        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb txn failed: {e}")))?;
        {
            let mut table = write_txn
                .open_table(FOLLOWERS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open followers table failed: {e}")))?;
            let _ = table.remove(edge_key.as_str());
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;

        if let Ok(mut conn) = self.get_redis().await {
            let f_key = format!("wou_following:{}", follower_id);
            let t_key = format!("wou_followers:{}", target_id);
            let _: Result<(), _> = conn.srem(f_key, target_id).await;
            let _: Result<(), _> = conn.srem(t_key, follower_id).await;
        }

        if let Some(mut follower) = self.get_account_by_id(follower_id).await? {
            follower.following_count = follower.following_count.saturating_sub(1);
            let _ = self.save_account(&follower).await;
        }
        if let Some(mut target) = self.get_account_by_id(target_id).await? {
            target.followers_count = target.followers_count.saturating_sub(1);
            let _ = self.save_account(&target).await;
        }

        Ok(())
    }

    pub async fn get_followers(&self, account_id: &str) -> Result<Vec<String>, WouError> {
        if let Ok(mut conn) = self.get_redis().await {
            let t_key = format!("wou_followers:{}", account_id);
            if let Ok(members) = conn.smembers::<_, Vec<String>>(t_key).await {
                if !members.is_empty() {
                    return Ok(members);
                }
            }
        }

        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(FOLLOWERS_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open followers table failed: {e}")))?;

        let mut followers = Vec::new();
        let target_suffix = format!(":{account_id}");
        for item in table.iter().map_err(|e| WouError::DatabaseError(e.to_string()))? {
            if let Ok((k, _)) = item {
                let key_str = k.value();
                if key_str.starts_with("follow:") && key_str.ends_with(&target_suffix) {
                    if let Some(f_id) = key_str.strip_prefix("follow:").and_then(|s| s.strip_suffix(&target_suffix)) {
                        followers.push(f_id.to_string());
                    }
                }
            }
        }
        Ok(followers)
    }

    pub async fn get_following(&self, account_id: &str) -> Result<Vec<String>, WouError> {
        if let Ok(mut conn) = self.get_redis().await {
            let f_key = format!("wou_following:{}", account_id);
            if let Ok(members) = conn.smembers::<_, Vec<String>>(f_key).await {
                if !members.is_empty() {
                    return Ok(members);
                }
            }
        }

        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(FOLLOWERS_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open followers table failed: {e}")))?;

        let mut following = Vec::new();
        let prefix = format!("follow:{account_id}:");
        for item in table.iter().map_err(|e| WouError::DatabaseError(e.to_string()))? {
            if let Ok((k, _)) = item {
                let key_str = k.value();
                if let Some(target_id) = key_str.strip_prefix(&prefix) {
                    following.push(target_id.to_string());
                }
            }
        }
        Ok(following)
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

    // ==========================================
    // CLANS & GUILDS
    // ==========================================

    pub async fn create_clan(&self, clan: &Clan, leader_member: &ClanMember) -> Result<(), WouError> {
        let tag = clan.tag.to_uppercase();
        let bytes = serde_json::to_vec(clan)
            .map_err(|e| WouError::Internal(format!("Failed to serialize clan: {e}")))?;
        let member_bytes = serde_json::to_vec(leader_member)
            .map_err(|e| WouError::Internal(format!("Failed to serialize clan member: {e}")))?;

        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut clans = write_txn
                .open_table(CLANS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open clans table failed: {e}")))?;

            if clans.get(tag.as_str()).map_err(|e| WouError::DatabaseError(e.to_string()))?.is_some() {
                return Err(WouError::Internal(format!("Clan tag [{tag}] is already taken")));
            }

            clans
                .insert(tag.as_str(), bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert clan failed: {e}")))?;

            let mut members = write_txn
                .open_table(CLAN_MEMBERS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open clan members table failed: {e}")))?;

            let member_key = format!("{tag}:{}", leader_member.account_id);
            members
                .insert(member_key.as_str(), member_bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert clan member failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;

        // Cache in Valkey
        if let Ok(mut conn) = self.get_redis().await {
            let _: Result<(), _> = conn.set_ex(format!("wou_clan:{tag}"), serde_json::to_string(clan).unwrap_or_default(), 86400).await;
        }

        Ok(())
    }

    pub async fn get_clan(&self, tag: &str) -> Result<Option<Clan>, WouError> {
        let clean_tag = tag.trim().to_uppercase();

        // 1. Try Valkey cache
        if let Ok(mut conn) = self.get_redis().await {
            if let Ok(Some(cached)) = conn.get::<_, Option<String>>(format!("wou_clan:{clean_tag}")).await {
                if let Ok(clan) = serde_json::from_str::<Clan>(&cached) {
                    return Ok(Some(clan));
                }
            }
        }

        // 2. Fallback to Redb
        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(CLANS_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open clans table failed: {e}")))?;

        match table.get(clean_tag.as_str()) {
            Ok(Some(val)) => {
                let clan: Clan = serde_json::from_slice(val.value())
                    .map_err(|e| WouError::Internal(format!("Clan deserialization failed: {e}")))?;
                Ok(Some(clan))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(WouError::DatabaseError(format!("Redb clan get failed: {e}"))),
        }
    }

    pub async fn get_clan_members(&self, tag: &str) -> Result<Vec<ClanMember>, WouError> {
        let clean_tag = tag.trim().to_uppercase();
        let prefix = format!("{clean_tag}:");

        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(CLAN_MEMBERS_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open clan members table failed: {e}")))?;

        let mut members = Vec::new();
        for item in table.range(prefix.as_str()..).map_err(|e| WouError::DatabaseError(format!("Range failed: {e}")))? {
            let (k, v) = item.map_err(|e| WouError::DatabaseError(format!("Entry failed: {e}")))?;
            let key = k.value();
            if !key.starts_with(&prefix) {
                break;
            }
            if let Ok(member) = serde_json::from_slice::<ClanMember>(v.value()) {
                members.push(member);
            }
        }

        Ok(members)
    }

    pub async fn join_clan(&self, tag: &str, member: &ClanMember) -> Result<(), WouError> {
        let clean_tag = tag.trim().to_uppercase();
        let member_bytes = serde_json::to_vec(member)
            .map_err(|e| WouError::Internal(format!("Failed to serialize member: {e}")))?;

        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut clans = write_txn
                .open_table(CLANS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open clans table failed: {e}")))?;

            let existing_bytes = {
                let clan_entry = clans.get(clean_tag.as_str()).map_err(|e| WouError::DatabaseError(e.to_string()))?;
                let Some(entry) = clan_entry else {
                    return Err(WouError::Internal(format!("Clan [{clean_tag}] not found")));
                };
                entry.value().to_vec()
            };

            let mut clan: Clan = serde_json::from_slice(&existing_bytes)
                .map_err(|e| WouError::Internal(format!("Clan parse failed: {e}")))?;

            clan.member_count += 1;
            let updated_bytes = serde_json::to_vec(&clan)
                .map_err(|e| WouError::Internal(format!("Serialize failed: {e}")))?;

            clans
                .insert(clean_tag.as_str(), updated_bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Update clan failed: {e}")))?;

            let mut members = write_txn
                .open_table(CLAN_MEMBERS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open clan members table failed: {e}")))?;

            let member_key = format!("{clean_tag}:{}", member.account_id);
            members
                .insert(member_key.as_str(), member_bytes.as_slice())
                .map_err(|e| WouError::DatabaseError(format!("Insert clan member failed: {e}")))?;
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;

        // Invalidate Valkey cache
        if let Ok(mut conn) = self.get_redis().await {
            let _: Result<(), _> = conn.del(format!("wou_clan:{clean_tag}")).await;
        }

        Ok(())
    }

    pub async fn leave_clan(&self, tag: &str, account_id: &str) -> Result<(), WouError> {
        let clean_tag = tag.trim().to_uppercase();
        let member_key = format!("{clean_tag}:{account_id}");

        let write_txn = self
            .redb
            .begin_write()
            .map_err(|e| WouError::DatabaseError(format!("Redb write txn failed: {e}")))?;
        {
            let mut members = write_txn
                .open_table(CLAN_MEMBERS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open clan members table failed: {e}")))?;

            members.remove(member_key.as_str())
                .map_err(|e| WouError::DatabaseError(format!("Remove member failed: {e}")))?;

            let mut clans = write_txn
                .open_table(CLANS_TABLE)
                .map_err(|e| WouError::DatabaseError(format!("Open clans table failed: {e}")))?;

            let existing_bytes = {
                let entry_opt = clans.get(clean_tag.as_str()).map_err(|e| WouError::DatabaseError(e.to_string()))?;
                entry_opt.map(|entry| entry.value().to_vec())
            };

            if let Some(bytes) = existing_bytes {
                let mut clan: Clan = serde_json::from_slice(&bytes)
                    .map_err(|e| WouError::Internal(format!("Clan parse failed: {e}")))?;

                if clan.member_count > 1 {
                    clan.member_count -= 1;
                    let updated_bytes = serde_json::to_vec(&clan).unwrap_or_default();
                    let _ = clans.insert(clean_tag.as_str(), updated_bytes.as_slice());
                } else {
                    // Last member left, remove clan
                    let _ = clans.remove(clean_tag.as_str());
                }
            }
        }
        write_txn
            .commit()
            .map_err(|e| WouError::DatabaseError(format!("Redb commit failed: {e}")))?;

        // Invalidate Valkey cache
        if let Ok(mut conn) = self.get_redis().await {
            let _: Result<(), _> = conn.del(format!("wou_clan:{clean_tag}")).await;
        }

        Ok(())
    }

    pub async fn list_clans(&self, limit: usize) -> Result<Vec<Clan>, WouError> {
        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(CLANS_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open clans table failed: {e}")))?;

        let mut list = Vec::new();
        for item in table.iter().map_err(|e| WouError::DatabaseError(format!("Iter failed: {e}")))? {
            let (_, v) = item.map_err(|e| WouError::DatabaseError(format!("Entry failed: {e}")))?;
            if let Ok(clan) = serde_json::from_slice::<Clan>(v.value()) {
                list.push(clan);
                if list.len() >= limit {
                    break;
                }
            }
        }

        // Sort by member count descending
        list.sort_by(|a, b| b.member_count.cmp(&a.member_count));

        Ok(list)
    }

    // ==========================================
    // PLAYER DISCOVERY & SEARCH
    // ==========================================

    pub async fn search_players(&self, query: &str, limit: usize) -> Result<Vec<PlayerSearchResult>, WouError> {
        let clean = query.trim().trim_start_matches('@').to_lowercase();
        if clean.is_empty() {
            return Ok(Vec::new());
        }

        let read_txn = self
            .redb
            .begin_read()
            .map_err(|e| WouError::DatabaseError(format!("Redb read txn failed: {e}")))?;
        let table = read_txn
            .open_table(PLAYERS_TABLE)
            .map_err(|e| WouError::DatabaseError(format!("Open players table failed: {e}")))?;

        let mut results = Vec::new();
        for item in table.iter().map_err(|e| WouError::DatabaseError(format!("Iter failed: {e}")))? {
            let (_, v) = item.map_err(|e| WouError::DatabaseError(format!("Entry failed: {e}")))?;
            if let Ok(account) = serde_json::from_slice::<PlayerAccount>(v.value()) {
                let matches_user = account.username.to_lowercase().contains(&clean);
                let matches_name = account.display_name.to_lowercase().contains(&clean);

                if matches_user || matches_name {
                    let animal_emoji = account.profile.custom_attributes.get("animal_emoji")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    results.push(PlayerSearchResult {
                        id: account.id,
                        username: account.username,
                        display_name: account.display_name,
                        avatar_url: account.profile.avatar_url,
                        animal_emoji,
                        clan_tag: account.clan_tag,
                    });

                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(results)
    }
}
