use wou_core::AuthProvider;
use wou_crypto::{generate_secure_otp, JwtManager, OAuthManager};

#[test]
fn test_oauth_authorization_url_building() {
    let oauth = OAuthManager::new();

    // Discord URL test
    let discord_url = oauth
        .build_authorization_url(
            &AuthProvider::Discord,
            "123456789",
            "https://id.worldofunreal.com/auth/callback",
            "test_state_123",
        )
        .unwrap();

    assert!(discord_url.starts_with("https://discord.com/api/oauth2/authorize"));
    assert!(discord_url.contains("client_id=123456789"));
    assert!(discord_url.contains("scope=identify%20email"));
    assert!(discord_url.contains("state=test_state_123"));

    // Google URL test
    let google_url = oauth
        .build_authorization_url(
            &AuthProvider::Google,
            "google_client_id_999",
            "https://id.worldofunreal.com/auth/callback",
            "state_google",
        )
        .unwrap();

    assert!(google_url.starts_with("https://accounts.google.com/o/oauth2/v2/auth"));
    assert!(google_url.contains("client_id=google_client_id_999"));
    assert!(google_url.contains("scope=openid%20profile%20email"));

    // Twitter URL test
    let twitter_url = oauth
        .build_authorization_url(
            &AuthProvider::Twitter,
            "twitter_client_id",
            "https://id.worldofunreal.com/auth/callback",
            "state_twitter",
        )
        .unwrap();

    assert!(twitter_url.starts_with("https://twitter.com/i/oauth2/authorize"));
    assert!(twitter_url.contains("code_challenge=challenge"));

    // Meta URL test
    let meta_url = oauth
        .build_authorization_url(
            &AuthProvider::Meta,
            "meta_app_id",
            "https://id.worldofunreal.com/auth/callback",
            "state_meta",
        )
        .unwrap();

    assert!(meta_url.starts_with("https://www.facebook.com/v19.0/dialog/oauth"));
    assert!(meta_url.contains("client_id=meta_app_id"));
}

#[test]
fn test_secure_otp_distribution_and_uniqueness() {
    let mut otps = std::collections::HashSet::new();
    for _ in 0..100 {
        let code = generate_secure_otp();
        assert_eq!(code.len(), 6);
        let num: u32 = code.parse().unwrap();
        assert!((100_000..=999_999).contains(&num));
        otps.insert(code);
    }
    // High entropy check: 100 random 6-digit OTPs should almost all be distinct
    assert!(otps.len() > 90);
}

#[test]
fn test_jwt_session_claims_roundtrip() {
    let jwt = JwtManager::new("production_quality_secret_key_testing_1234567890");
    let token = jwt
        .issue_token(
            "usr_test_123",
            "Commander_Alpha",
            Some("alpha@worldofunreal.com".into()),
            wou_core::GameContext::ShadowsOfWar,
            86400,
        )
        .unwrap();

    let claims = jwt.verify_token(&token).unwrap();
    assert_eq!(claims.sub, "usr_test_123");
    assert_eq!(claims.name, "Commander_Alpha");
    assert_eq!(claims.email, Some("alpha@worldofunreal.com".into()));
    assert_eq!(claims.context, wou_core::GameContext::ShadowsOfWar);
}
