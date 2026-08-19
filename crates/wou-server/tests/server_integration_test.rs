use wou_core::{AuthProvider, GameContext, PendingOtp, PlayerAccount};
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

    // 1. Create Anonymous Account
    let anon_id = uuid::Uuid::new_v4().to_string();
    let mut account = PlayerAccount::new_anonymous(anon_id.clone(), Some("Commander_Test".to_string()));
    assert!(account.is_anonymous());

    storage.save_account(&account).await.unwrap();

    // 2. Fetch and Verify Anonymous Account
    let fetched = storage.get_account_by_id(&anon_id).await.unwrap().unwrap();
    assert_eq!(fetched.display_name, "Commander_Test");
    assert!(fetched.is_anonymous());

    // 3. Request & Verify OTP (if Redis is running)
    let test_email = format!("tester_{}@worldofunreal.com", uuid::Uuid::new_v4());
    let otp = PendingOtp {
        code: "654321".to_string(),
        account_id: Some(anon_id.clone()),
        email: test_email.clone(),
        context: GameContext::ShadowsOfWar,
        newsletter_opt_in: true,
        requested_at: chrono::Utc::now().timestamp() as u64,
    };

    match storage.save_pending_otp(&otp, 600).await {
        Ok(_) => {
            let consumed = storage.get_and_consume_otp(&test_email, "654321").await.unwrap();
            assert_eq!(consumed.email, test_email);
        }
        Err(e) => {
            println!("Notice: Redis/Valkey offline in local test environment ({e}). Skipping hot OTP test.");
        }
    }

    // 5. Promote Anonymous Account to Permanent Verified Email
    account.email = Some(test_email.clone());
    account.newsletter_opt_in = true;
    account.link_identity(AuthProvider::Email, test_email.clone());
    storage.save_account(&account).await.unwrap();

    // 6. Check that account is no longer anonymous and is indexed by email
    let by_email = storage.find_account_by_email(&test_email).await.unwrap().unwrap();
    assert_eq!(by_email.id, anon_id);
    assert!(!by_email.is_anonymous());
    assert_eq!(by_email.email, Some(test_email));
    assert!(by_email.has_provider(&AuthProvider::Email));

    // 7. Link CrazyGames Identity
    account.link_identity(AuthProvider::CrazyGames, "cg_user_998877".to_string());
    storage.save_account(&account).await.unwrap();

    let by_cg = storage
        .find_account_by_identity(&AuthProvider::CrazyGames, "cg_user_998877")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_cg.id, anon_id);

    // 8. Issue & Verify JWT Session Token
    let jwt = JwtManager::new("integration_test_secret_key_123456789012345678901234567890");
    let token = jwt
        .issue_token(&account.id, &account.display_name, account.email.clone(), GameContext::ShadowsOfWar, 3600)
        .unwrap();

    let claims = jwt.verify_token(&token).unwrap();
    assert_eq!(claims.sub, anon_id);
    assert_eq!(claims.name, "Commander_Test");

    // Clean up temporary redb file
    let _ = std::fs::remove_file(tmp_db_path);
}
