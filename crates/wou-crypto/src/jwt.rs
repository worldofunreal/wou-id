use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use wou_core::{GameContext, SessionClaims, WouError};

#[derive(Clone)]
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtManager {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    /// Issue a new signed JWT Session Token for an account.
    pub fn issue_token(
        &self,
        account_id: &str,
        name: &str,
        email: Option<String>,
        context: GameContext,
        validity_seconds: u64,
    ) -> Result<String, WouError> {
        let now = chrono::Utc::now().timestamp() as u64;
        let claims = SessionClaims {
            sub: account_id.to_string(),
            name: name.to_string(),
            email,
            context,
            iat: now,
            exp: now + validity_seconds,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| WouError::Internal(format!("Failed to encode JWT: {e}")))
    }

    /// Verify and decode a JWT Session Token.
    pub fn verify_token(&self, token: &str) -> Result<SessionClaims, WouError> {
        let validation = Validation::default();
        decode::<SessionClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| WouError::Unauthorized(format!("Invalid token: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_issue_and_verify() {
        let mgr = JwtManager::new("super_secret_test_key_for_wou_id_testing_purposes_12345");
        let token = mgr
            .issue_token(
                "usr_12345",
                "Commander_Alpha",
                Some("alpha@shadowsofwar.io".to_string()),
                GameContext::ShadowsOfWar,
                3600,
            )
            .unwrap();

        let claims = mgr.verify_token(&token).unwrap();
        assert_eq!(claims.sub, "usr_12345");
        assert_eq!(claims.name, "Commander_Alpha");
        assert_eq!(claims.email, Some("alpha@shadowsofwar.io".to_string()));
        assert_eq!(claims.context, GameContext::ShadowsOfWar);
    }
}
