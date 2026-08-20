use serde::{Deserialize, Serialize};
use wou_core::{AuthProvider, WouError};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OAuthUserInfo {
    pub provider: AuthProvider,
    pub external_id: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Clone)]
pub struct OAuthManager {
    http: reqwest::Client,
}

impl OAuthManager {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    /// Build Authorization Redirect URL for the requested Social Provider.
    pub fn build_authorization_url(
        &self,
        provider: &AuthProvider,
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> Result<String, WouError> {
        let redirect_encoded = urlencoding::encode(redirect_uri);
        let state_encoded = urlencoding::encode(state);

        match provider {
            AuthProvider::Discord => Ok(format!(
                "https://discord.com/api/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=identify%20email&state={}",
                client_id, redirect_encoded, state_encoded
            )),
            AuthProvider::Google => Ok(format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile%20email&state={}",
                client_id, redirect_encoded, state_encoded
            )),
            AuthProvider::Twitter => Ok(format!(
                "https://twitter.com/i/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&scope=users.read%20tweet.read&state={}&code_challenge=challenge&code_challenge_method=plain",
                client_id, redirect_encoded, state_encoded
            )),
            AuthProvider::Meta => Ok(format!(
                "https://www.facebook.com/v19.0/dialog/oauth?client_id={}&redirect_uri={}&state={}&scope=public_profile,email",
                client_id, redirect_encoded, state_encoded
            )),
            _ => Err(WouError::ProviderVerificationFailed(format!(
                "Provider {} does not support OAuth2 authorization URL",
                provider.as_str()
            ))),
        }
    }

    /// Exchange an OAuth2 authorization code for verified user profile info.
    pub async fn exchange_code_for_user(
        &self,
        provider: &AuthProvider,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<OAuthUserInfo, WouError> {
        match provider {
            AuthProvider::Discord => self.exchange_discord(code, client_id, client_secret, redirect_uri).await,
            AuthProvider::Google => self.exchange_google(code, client_id, client_secret, redirect_uri).await,
            AuthProvider::Twitter => self.exchange_twitter(code, client_id, client_secret, redirect_uri).await,
            AuthProvider::Meta => self.exchange_meta(code, client_id, client_secret, redirect_uri).await,
            _ => Err(WouError::ProviderVerificationFailed(format!(
                "Unsupported OAuth2 provider: {}",
                provider.as_str()
            ))),
        }
    }

    async fn exchange_discord(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<OAuthUserInfo, WouError> {
        #[derive(Deserialize)]
        struct DiscordTokenResp {
            access_token: String,
        }

        #[derive(Deserialize)]
        struct DiscordUserResp {
            id: String,
            username: String,
            global_name: Option<String>,
            email: Option<String>,
            avatar: Option<String>,
        }

        let params = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ];

        let token_resp: DiscordTokenResp = self
            .http
            .post("https://discord.com/api/v10/oauth2/token")
            .form(&params)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Discord token exchange HTTP error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Discord token JSON parse error: {e}")))?;

        let user_resp: DiscordUserResp = self
            .http
            .get("https://discord.com/api/v10/users/@me")
            .bearer_auth(&token_resp.access_token)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Discord userinfo HTTP error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Discord userinfo JSON parse error: {e}")))?;

        let avatar_url = user_resp
            .avatar
            .map(|hash| format!("https://cdn.discordapp.com/avatars/{}/{}.png", user_resp.id, hash));

        Ok(OAuthUserInfo {
            provider: AuthProvider::Discord,
            external_id: user_resp.id,
            display_name: user_resp.global_name.or(Some(user_resp.username)),
            email: user_resp.email,
            avatar_url,
        })
    }

    async fn exchange_google(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<OAuthUserInfo, WouError> {
        #[derive(Deserialize)]
        struct GoogleTokenResp {
            access_token: String,
        }

        #[derive(Deserialize)]
        struct GoogleUserResp {
            sub: String,
            name: Option<String>,
            email: Option<String>,
            picture: Option<String>,
        }

        let params = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ];

        let token_resp: GoogleTokenResp = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Google token exchange error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Google token parse error: {e}")))?;

        let user_resp: GoogleUserResp = self
            .http
            .get("https://openidconnect.googleapis.com/v1/userinfo")
            .bearer_auth(&token_resp.access_token)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Google userinfo error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Google userinfo parse error: {e}")))?;

        Ok(OAuthUserInfo {
            provider: AuthProvider::Google,
            external_id: user_resp.sub,
            display_name: user_resp.name,
            email: user_resp.email,
            avatar_url: user_resp.picture,
        })
    }

    async fn exchange_twitter(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<OAuthUserInfo, WouError> {
        #[derive(Deserialize)]
        struct TwitterTokenResp {
            access_token: String,
        }

        #[derive(Deserialize)]
        struct TwitterData {
            id: String,
            name: String,
            username: String,
            profile_image_url: Option<String>,
        }

        #[derive(Deserialize)]
        struct TwitterUserResp {
            data: TwitterData,
        }

        let params = [
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", "challenge"),
        ];

        let token_resp: TwitterTokenResp = self
            .http
            .post("https://api.twitter.com/2/oauth2/token")
            .basic_auth(client_id, Some(client_secret))
            .form(&params)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Twitter token exchange error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Twitter token parse error: {e}")))?;

        let user_resp: TwitterUserResp = self
            .http
            .get("https://api.twitter.com/2/users/me?user.fields=profile_image_url")
            .bearer_auth(&token_resp.access_token)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Twitter userinfo error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Twitter userinfo parse error: {e}")))?;

        Ok(OAuthUserInfo {
            provider: AuthProvider::Twitter,
            external_id: user_resp.data.id,
            display_name: Some(user_resp.data.name).or(Some(user_resp.data.username)),
            email: None,
            avatar_url: user_resp.data.profile_image_url,
        })
    }

    async fn exchange_meta(
        &self,
        code: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
    ) -> Result<OAuthUserInfo, WouError> {
        #[derive(Deserialize)]
        struct MetaTokenResp {
            access_token: String,
        }

        #[derive(Deserialize)]
        struct MetaUserResp {
            id: String,
            name: Option<String>,
            email: Option<String>,
        }

        let url = format!(
            "https://graph.facebook.com/v19.0/oauth/access_token?client_id={}&client_secret={}&redirect_uri={}&code={}",
            client_id, client_secret, urlencoding::encode(redirect_uri), code
        );

        let token_resp: MetaTokenResp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Meta token exchange error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Meta token parse error: {e}")))?;

        let user_url = format!(
            "https://graph.facebook.com/me?fields=id,name,email&access_token={}",
            token_resp.access_token
        );

        let user_resp: MetaUserResp = self
            .http
            .get(&user_url)
            .send()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Meta userinfo error: {e}")))?
            .json()
            .await
            .map_err(|e| WouError::ProviderVerificationFailed(format!("Meta userinfo parse error: {e}")))?;

        Ok(OAuthUserInfo {
            provider: AuthProvider::Meta,
            external_id: user_resp.id,
            display_name: user_resp.name,
            email: user_resp.email,
            avatar_url: None,
        })
    }
}
