use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    Json,
};
use serde_json::json;
use wou_core::SessionClaims;

use crate::state::AppState;

/// Sovereign type-level authentication guard.
/// Ensures zero-overhead verification in CPU L1 cache, zero DB roundtrips.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub account_id: String,
    pub claims: SessionClaims,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthSession
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Missing Authorization header" })),
                )
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .unwrap_or(auth_header)
            .trim();

        if token.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Empty bearer token" })),
            ));
        }

        let app_state = AppState::from_ref(state);
        let claims = app_state.jwt.verify_token(token).map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": format!("Invalid session token: {e}") })),
            )
        })?;

        let account_id = claims.sub.clone();

        Ok(AuthSession { account_id, claims })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use std::sync::Arc;
    use wou_core::GameContext;
    use wou_crypto::{JwtManager, OAuthManager};
    use wou_mail::{StalwartMailer, StalwartMailerConfig};
    use wou_storage::WouStorage;

    #[tokio::test]
    async fn test_auth_session_missing_header() {
        let jwt = JwtManager::new("secret_test_key_123456789012345678901234567890");
        let jwt_arc = Arc::new(jwt);
        let storage = match WouStorage::new("redis://127.0.0.1:6379/0", "/tmp/mock_auth.redb") {
            Ok(s) => s,
            Err(_) => return, // Skip if redis not running locally
        };
        let mailer = StalwartMailer::new(StalwartMailerConfig {
            smtp_host: "127.0.0.1".into(),
            smtp_port: 587,
            domain_passwords: std::collections::HashMap::new(),
        })
        .unwrap();

        let state = AppState {
            storage,
            mailer,
            jwt: jwt_arc.clone(),
            oauth: Arc::new(OAuthManager::new()),
            otp_expiry_seconds: 600,
        };

        // 1. Missing header
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();
        let res = AuthSession::from_request_parts(&mut parts, &state).await;
        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // 2. Valid token
        let token = jwt_arc
            .issue_token(
                "player_123",
                "Falcon Prime",
                Some("falcon@worldofunreal.com".into()),
                GameContext::ShadowsOfWar,
                3600,
            )
            .unwrap();

        let req = Request::builder()
            .header("Authorization", format!("Bearer {token}"))
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let session = AuthSession::from_request_parts(&mut parts, &state).await.unwrap();
        assert_eq!(session.account_id, "player_123");
        assert_eq!(session.claims.name, "Falcon Prime");

        // 3. Tampered token
        let req = Request::builder()
            .header("Authorization", format!("Bearer {token}tampered"))
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        let res = AuthSession::from_request_parts(&mut parts, &state).await;
        assert!(res.is_err());
        let (status, _) = res.unwrap_err();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
