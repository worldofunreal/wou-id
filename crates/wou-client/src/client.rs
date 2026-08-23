use serde::{Deserialize, Serialize};
use wou_core::{GameContext, PlayerAccount, WouError};

#[derive(Clone)]
pub struct WouClient {
    base_url: String,
    http: reqwest::Client,
}

#[derive(Serialize)]
struct AnonymousPayload {
    account_id: Option<String>,
    display_name: Option<String>,
    context: GameContext,
}

#[derive(Deserialize)]
struct AnonymousResponse {
    account: PlayerAccount,
    session_token: String,
}

#[derive(Serialize)]
struct OtpRequestPayload {
    email: String,
    account_id: Option<String>,
    context: GameContext,
    newsletter_opt_in: bool,
}

#[derive(Serialize)]
struct OtpVerifyPayload {
    email: String,
    code: String,
    account_id: Option<String>,
    context: GameContext,
}

#[derive(Deserialize)]
pub struct OtpVerifyResult {
    pub status: String,
    pub account: PlayerAccount,
    pub session_token: String,
    pub is_new_account: bool,
}

#[derive(Serialize)]
struct LinkCrazyGamesPayload {
    account_id: String,
    token: String,
    context: GameContext,
}

#[derive(Serialize)]
struct LinkWeb3Payload {
    account_id: String,
    address_or_pubkey: String,
    message: String,
    signature: String,
    context: GameContext,
}

#[derive(Deserialize)]
struct LinkResponse {
    #[allow(dead_code)]
    status: String,
    account: PlayerAccount,
}

impl WouClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Step 0: Start or restore an anonymous player session (Zero Friction).
    pub async fn start_or_restore_anonymous(
        &self,
        stored_id: Option<String>,
        display_name: Option<String>,
        context: GameContext,
    ) -> Result<(PlayerAccount, String), WouError> {
        let url = format!("{}/api/v1/auth/anonymous", self.base_url);
        let payload = AnonymousPayload {
            account_id: stored_id,
            display_name,
            context,
        };

        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(WouError::Internal(format!("Anonymous auth failed: {err_text}")));
        }

        let body: AnonymousResponse = resp
            .json()
            .await
            .map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))?;

        Ok((body.account, body.session_token))
    }

    /// Step 1: Request 6-digit OTP code sent via Stalwart to player's email.
    pub async fn request_otp(
        &self,
        email: &str,
        account_id: Option<String>,
        context: GameContext,
        newsletter_opt_in: bool,
    ) -> Result<(), WouError> {
        let url = format!("{}/api/v1/auth/otp/request", self.base_url);
        let payload = OtpRequestPayload {
            email: email.to_string(),
            account_id,
            context,
            newsletter_opt_in,
        };

        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(WouError::Internal(format!("OTP request failed: {err_text}")));
        }

        Ok(())
    }

    /// Step 2: Verify 6-digit OTP code, link email, and promote account.
    pub async fn verify_otp(
        &self,
        email: &str,
        code: &str,
        account_id: Option<String>,
        context: GameContext,
    ) -> Result<OtpVerifyResult, WouError> {
        let url = format!("{}/api/v1/auth/otp/verify", self.base_url);
        let payload = OtpVerifyPayload {
            email: email.to_string(),
            code: code.to_string(),
            account_id,
            context,
        };

        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(WouError::Unauthorized(format!("OTP verification failed: {err_text}")));
        }

        let body: OtpVerifyResult = resp
            .json()
            .await
            .map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))?;

        Ok(body)
    }

    /// Step 3: Link CrazyGames portal identity.
    pub async fn link_crazygames(
        &self,
        account_id: &str,
        token: &str,
        context: GameContext,
    ) -> Result<PlayerAccount, WouError> {
        let url = format!("{}/api/v1/auth/link/crazygames", self.base_url);
        let payload = LinkCrazyGamesPayload {
            account_id: account_id.to_string(),
            token: token.to_string(),
            context,
        };

        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(WouError::Internal(format!("CrazyGames link failed: {err_text}")));
        }

        let body: LinkResponse = resp
            .json()
            .await
            .map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))?;

        Ok(body.account)
    }

    /// Step 4: Link Web3 Ethereum or Solana Wallet.
    pub async fn link_web3(
        &self,
        account_id: &str,
        is_ethereum: bool,
        address: &str,
        message: &str,
        signature: &str,
        context: GameContext,
    ) -> Result<PlayerAccount, WouError> {
        let endpoint = if is_ethereum { "ethereum" } else { "solana" };
        let url = format!("{}/api/v1/auth/link/{}", self.base_url, endpoint);
        let payload = LinkWeb3Payload {
            account_id: account_id.to_string(),
            address_or_pubkey: address.to_string(),
            message: message.to_string(),
            signature: signature.to_string(),
            context,
        };

        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            return Err(WouError::Internal(format!("Web3 link failed: {err_text}")));
        }

        let body: LinkResponse = resp
            .json()
            .await
            .map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))?;

        Ok(body.account)
    }

    /// Step 5: Fetch player profile by account ID.
    pub async fn get_profile(&self, account_id: &str) -> Result<PlayerAccount, WouError> {
        let url = format!("{}/api/v1/user/profile/{}", self.base_url, account_id);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            return Err(WouError::AccountNotFound(format!("Profile not found: {err}")));
        }

        resp.json().await.map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))
    }

    /// Step 6: Fetch player profile by username.
    pub async fn get_by_username(&self, username: &str) -> Result<PlayerAccount, WouError> {
        let url = format!("{}/api/v1/user/by-username/{}", self.base_url, username);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            return Err(WouError::AccountNotFound(format!("User @{username} not found: {err}")));
        }

        resp.json().await.map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))
    }

    /// Step 7: Check username availability.
    pub async fn check_username(&self, username: &str) -> Result<bool, WouError> {
        let url = format!("{}/api/v1/user/check-username/{}", self.base_url, username);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        #[derive(Deserialize)]
        struct AvailResp {
            available: bool,
        }

        let body: AvailResp = resp.json().await.map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))?;
        Ok(body.available)
    }

    /// Step 8: Follow a player.
    pub async fn follow_user(&self, follower_id: &str, target_id: &str) -> Result<(), WouError> {
        let url = format!("{}/api/v1/social/follow/{}", self.base_url, target_id);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "follower_id": follower_id }))
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            return Err(WouError::Internal(format!("Follow failed: {err}")));
        }

        Ok(())
    }

    /// Step 9: Unfollow a player.
    pub async fn unfollow_user(&self, follower_id: &str, target_id: &str) -> Result<(), WouError> {
        let url = format!("{}/api/v1/social/unfollow/{}", self.base_url, target_id);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "follower_id": follower_id }))
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            return Err(WouError::Internal(format!("Unfollow failed: {err}")));
        }

        Ok(())
    }

    /// Step 10: Fetch global activity feed.
    pub async fn get_global_feed(&self) -> Result<Vec<wou_core::SocialActivity>, WouError> {
        let url = format!("{}/api/v1/social/feed", self.base_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| WouError::Internal(format!("HTTP request failed: {e}")))?;

        if !resp.status().is_success() {
            let err = resp.text().await.unwrap_or_default();
            return Err(WouError::Internal(format!("Feed fetch failed: {err}")));
        }

        resp.json().await.map_err(|e| WouError::Internal(format!("JSON decode failed: {e}")))
    }
}
