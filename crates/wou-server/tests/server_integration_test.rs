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
