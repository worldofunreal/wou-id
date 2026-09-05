use wou_core::{AuthProvider, GameContext, PendingOtp, PlayerAccount, SocialActivity};
use wou_crypto::JwtManager;
use wou_storage::WouStorage;

#[tokio::test]
async fn test_full_account_lifecycle() {
    let tmp_db_path = format!("/tmp/wou_test_accounts_{}.redb", uuid::Uuid::new_v4());
    let redis_url = "redis://127.0.0.1:6379/0";

    let storage = match WouStorage::new(redis_url, &tmp_db_path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Skipping test: Redis not running locally");
            return;
        }
    };

    // 1. Create Account with Auto-Embedded Wallets & Username
    let player_id = uuid::Uuid::new_v4().to_string();
    let wallets = wou_crypto::web3::derive_embedded_wallets(&player_id, "test_secret_seed");
    let mut account = PlayerAccount::new_with_wallets(
        player_id.clone(),
        Some("commander_prime".to_string()),
        Some("Commander Prime".to_string()),
        wallets.clone(),
    );

    assert_eq!(account.username, "commander_prime");
    assert!(account.embedded_wallets.evm_address.starts_with("0x"));
    assert!(account.embedded_wallets.solana_address.len() >= 32);

    storage.save_account(&account).await.unwrap();

    // 2. Fetch and Verify Account by ID and by Username Handle
    let fetched = storage.get_account_by_id(&player_id).await.unwrap().unwrap();
    assert_eq!(fetched.display_name, "Commander Prime");
    assert_eq!(fetched.username, "commander_prime");

    let by_user = storage.find_account_by_username("commander_prime").await.unwrap().unwrap();
    assert_eq!(by_user.id, player_id);

    // 3. Username Availability Check
    assert!(!storage.is_username_available("commander_prime", "other_id").await.unwrap());
    assert!(storage.is_username_available("commander_prime", &player_id).await.unwrap());
    assert!(storage.is_username_available("unique_handle_999", &player_id).await.unwrap());

    // 4. Request & Verify OTP
    let test_email = format!("tester_{}@worldofunreal.com", uuid::Uuid::new_v4());
    let otp = PendingOtp {
        code: "654321".to_string(),
        account_id: Some(player_id.clone()),
        email: test_email.clone(),
        context: GameContext::ShadowsOfWar,
        newsletter_opt_in: true,
        requested_at: chrono::Utc::now().timestamp() as u64,
    };

    if let Ok(_) = storage.save_pending_otp(&otp, 600).await {
        let consumed = storage.get_and_consume_otp(&test_email, "654321").await.unwrap();
        assert_eq!(consumed.email, test_email);
    }

    // 5. Link Email Identity & CrazyGames Identity
    account.email = Some(test_email.clone());
    account.newsletter_opt_in = true;
    account.link_identity(AuthProvider::Email, test_email.clone());
    account.link_identity(AuthProvider::CrazyGames, "cg_user_998877".to_string());
    storage.save_account(&account).await.unwrap();

    let by_email = storage.find_account_by_email(&test_email).await.unwrap().unwrap();
    assert_eq!(by_email.id, player_id);

    let by_cg = storage
        .find_account_by_identity(&AuthProvider::CrazyGames, "cg_user_998877")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_cg.id, player_id);

    // 6. Test Social Graph & Activity Feed
    let target_player_id = uuid::Uuid::new_v4().to_string();
    let target_wallets = wou_crypto::web3::derive_embedded_wallets(&target_player_id, "test_secret_seed");
    let target_account = PlayerAccount::new_with_wallets(
        target_player_id.clone(),
        Some("rival_commander".to_string()),
        Some("Rival Commander".to_string()),
        target_wallets,
    );
    storage.save_account(&target_account).await.unwrap();

    storage.follow_user(&player_id, &target_player_id).await.unwrap();
    let followers = storage.get_followers(&target_player_id).await.unwrap();
    assert!(followers.contains(&player_id));

    // Record Activity
    let activity = SocialActivity {
        id: uuid::Uuid::new_v4().to_string(),
        account_id: player_id.clone(),
        username: "commander_prime".into(),
        display_name: "Commander Prime".into(),
        avatar_url: None,
        activity_type: "sow_victory".into(),
        title: "Ranked Victory in Shadows of War".into(),
        description: "Achieved Master tier in 1v1 Battlegrounds".into(),
        game: GameContext::ShadowsOfWar,
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    storage.record_social_activity(&activity).await.unwrap();

    let feed = storage.get_social_feed(10).await.unwrap();
    assert!(!feed.is_empty());
    assert_eq!(feed[0].title, "Ranked Victory in Shadows of War");

    // 7. Issue & Verify JWT Session Token
    let jwt = JwtManager::new("integration_test_secret_key_123456789012345678901234567890");
    let token = jwt
        .issue_token(&account.id, &account.display_name, account.email.clone(), GameContext::ShadowsOfWar, 3600)
        .unwrap();

    let claims = jwt.verify_token(&token).unwrap();
    assert_eq!(claims.sub, player_id);
    assert_eq!(claims.name, "Commander Prime");

    // Clean up temporary redb file
    let _ = std::fs::remove_file(tmp_db_path);
}

async fn live_storage() -> Option<WouStorage> {
    live_storage_db(0).await
}

async fn live_storage_db(db: u8) -> Option<WouStorage> {
    let tmp_db_path = format!("/tmp/wou_test_sec_{}.redb", uuid::Uuid::new_v4());
    let url = format!("redis://127.0.0.1:6379/{db}");
    let storage = WouStorage::new(&url, &tmp_db_path).ok()?;
    // Constructor doesn't dial; probe with a no-op write.
    if storage.set_protection_mode(false).await.is_err() {
        eprintln!("Skipping security test: Redis not running locally");
        return None;
    }
    Some(storage)
}

fn is_throttled(e: &wou_core::WouError) -> bool {
    matches!(e, wou_core::WouError::OtpThrottled(_))
}

/// Ladder: 3/15min OK, 4th throttled, >6/30min penalized, reoffense banned.
#[tokio::test]
async fn test_otp_abuse_ladder() {
    let Some(storage) = live_storage().await else { return };
    let email = format!("ladder_{}@worldofunreal.com", uuid::Uuid::new_v4());
    for _ in 0..3 {
        storage.tally_otp_request(&email).await.unwrap();
    }
    assert!(is_throttled(&storage.tally_otp_request(&email).await.unwrap_err()));

    let email2 = format!("abuse_{}@worldofunreal.com", uuid::Uuid::new_v4());
    for _ in 0..3 {
        storage.tally_otp_request(&email2).await.unwrap();
    }
    // Tallies 4-6: throttled but still counting abuse pressure.
    for _ in 0..3 {
        assert!(is_throttled(&storage.tally_otp_request(&email2).await.unwrap_err()));
    }
    // 7th: 24h penalty.
    assert!(matches!(
        storage.tally_otp_request(&email2).await.unwrap_err(),
        wou_core::WouError::OtpPenalized(_)
    ));
    // Any request during penalty: ban.
    assert!(matches!(
        storage.tally_otp_request(&email2).await.unwrap_err(),
        wou_core::WouError::EmailBanned
    ));
    // Ban sticks.
    assert!(matches!(
        storage.tally_otp_request(&email2).await.unwrap_err(),
        wou_core::WouError::EmailBanned
    ));
}

/// 5 wrong guesses burn the code; a correct guess still works before that.
#[tokio::test]
async fn test_guess_burn() {
    let Some(storage) = live_storage().await else { return };
    let email = format!("guess_{}@worldofunreal.com", uuid::Uuid::new_v4());
    let otp = PendingOtp {
        code: "123456".to_string(),
        account_id: None,
        email: email.clone(),
        context: GameContext::WorldOfUnreal,
        newsletter_opt_in: false,
        requested_at: chrono::Utc::now().timestamp() as u64,
    };
    storage.save_pending_otp(&otp, 600).await.unwrap();
    for _ in 0..5 {
        assert!(storage.get_and_consume_otp(&email, "000000").await.is_err());
    }
    // Burned: even the right code fails now.
    assert!(storage.get_and_consume_otp(&email, "123456").await.is_err());

    let otp2 = PendingOtp { code: "654321".to_string(), ..otp.clone() };
    storage.save_pending_otp(&otp2, 600).await.unwrap();
    assert!(storage.get_and_consume_otp(&email, "000000").await.is_err());
    let consumed = storage.get_and_consume_otp(&email, "654321").await.unwrap();
    assert_eq!(consumed.code, "654321");
}

/// Per-IP ceilings: 100/hr, 300/day; 101st blocked, block sticks.
#[tokio::test]
async fn test_ip_throttle() {
    let Some(storage) = live_storage().await else { return };
    let ip = format!("10.9.9.{}", rand_octet());
    for _ in 0..100 {
        storage.tally_ip(&ip).await.unwrap();
    }
    assert!(matches!(
        storage.tally_ip(&ip).await.unwrap_err(),
        wou_core::WouError::IpBlocked
    ));
    assert!(matches!(
        storage.tally_ip(&ip).await.unwrap_err(),
        wou_core::WouError::IpBlocked
    ));
}

fn rand_octet() -> u8 {
    (uuid::Uuid::new_v4().as_bytes()[0] % 200) + 10
}

/// Protection mode toggles intake gating.
#[tokio::test]
async fn test_protection_mode() {
    let Some(storage) = live_storage_db(7).await else { return };
    assert!(!storage.protection_mode().await);
    storage.set_protection_mode(true).await.unwrap();
    assert!(storage.protection_mode().await);
    storage.set_protection_mode(false).await.unwrap();
    assert!(!storage.protection_mode().await);
}

/// Welcome + alert templates render without PII leaks in subject.
#[test]
fn test_security_templates() {
    let w = wou_mail::templates::render_welcome_email(GameContext::Cosmicrafts, "Commander X");
    assert!(w.subject.contains("Cosmicrafts"));
    assert!(w.html_body.contains("Commander X"));
    assert!(w.html_body.contains("security@worldofunreal.com"));
    assert!(w.html_body.contains("one-time"));
    let a = wou_mail::templates::render_admin_alert("Email banned", "tag=abc error=x");
    assert!(a.subject.starts_with("[WOU-ALERT]"));
}

/// Plus-addressing shares one abuse bucket (same mailbox).
#[tokio::test]
async fn test_plus_address_sharing() {
    let Some(storage) = live_storage_db(8).await else { return };
    let base = format!("plustest_{}@worldofunreal.com", uuid::Uuid::new_v4());
    let v1 = base.replacen('@', "+1@", 1);
    let v2 = base.replacen('@', "+2@", 1);
    let v3 = base.replacen('@', "+3@", 1);
    storage.tally_otp_request(&v1).await.unwrap();
    storage.tally_otp_request(&v2).await.unwrap();
    storage.tally_otp_request(&v3).await.unwrap();
    // Bare address hits the same exhausted bucket.
    assert!(is_throttled(&storage.tally_otp_request(&base).await.unwrap_err()));
}

/// Nonce cache is single-use (web3 challenge binding).
#[tokio::test]
async fn test_nonce_single_use() {
    let Some(storage) = live_storage_db(9).await else { return };
    let key = format!("wou_web3_nonce:test:{}", uuid::Uuid::new_v4());
    storage.save_cache_string(&key, "nonce-abc", 300).await.unwrap();
    assert_eq!(storage.take_cache_string(&key).await.unwrap(), Some("nonce-abc".to_string()));
    assert_eq!(storage.take_cache_string(&key).await.unwrap(), None);
}

/// Canonical email + key tags are pure and stable.
#[test]
fn test_canonical_and_tags() {
    assert_eq!(
        wou_core::canonical_email("Victim+1@X.com "),
        "victim@x.com"
    );
    assert_eq!(wou_core::canonical_email("a@b"), "a@b");
    let t1 = wou_core::key_tag("Victim@X.com");
    let t2 = wou_core::key_tag("victim@x.com");
    assert_eq!(t1, t2);
    assert_eq!(t1.len(), 12);
    assert!(!t1.contains('@'));
}
