use serde_json::json;

/// Outbound push clients. Stateless; secrets come from env at call time.
pub struct BotClients {
    http: reqwest::Client,
}

impl BotClients {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    fn tg_token() -> Option<String> {
        std::env::var("TELEGRAM_BOT_TOKEN").ok().filter(|s| !s.is_empty())
    }

    fn dc_token() -> Option<String> {
        std::env::var("DISCORD_BOT_TOKEN").ok().filter(|s| !s.is_empty())
    }

    pub fn telegram_configured() -> bool {
        Self::tg_token().is_some()
    }

    pub fn discord_configured() -> bool {
        Self::dc_token().is_some() && std::env::var("DISCORD_APP_ID").ok().is_some_and(|s| !s.is_empty())
    }

    /// Push an approve/deny prompt to a Telegram chat for a QR challenge.
    pub async fn telegram_qr_push(&self, chat_id: &str, challenge_id: &str) -> Result<(), String> {
        let token = Self::tg_token().ok_or("telegram not configured")?;
        let res = self
            .http
            .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
            .json(&json!({
                "chat_id": chat_id,
                "text": "Hyper sign-in requested. Approve?",
                "reply_markup": { "inline_keyboard": [[
                    { "text": "Approve", "callback_data": format!("qr:ok:{challenge_id}") },
                    { "text": "Deny", "callback_data": format!("qr:no:{challenge_id}") },
                ]]},
            }))
            .send()
            .await
            .map_err(|e| format!("telegram send failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("telegram rejected: {}", res.status()));
        }
        Ok(())
    }

    pub async fn answer_telegram_callback(&self, callback_id: &str, text: &str) -> Result<(), String> {
        let token = Self::tg_token().ok_or("telegram not configured")?;
        let res = self
            .http
            .post(format!("https://api.telegram.org/bot{token}/answerCallbackQuery"))
            .json(&json!({ "callback_query_id": callback_id, "text": text }))
            .send()
            .await
            .map_err(|e| format!("telegram callback failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("telegram rejected: {}", res.status()));
        }
        Ok(())
    }

    pub async fn telegram_text(&self, chat_id: &str, text: &str) -> Result<(), String> {
        let token = Self::tg_token().ok_or("telegram not configured")?;
        let res = self
            .http
            .post(format!("https://api.telegram.org/bot{token}/sendMessage"))
            .json(&json!({ "chat_id": chat_id, "text": text }))
            .send()
            .await
            .map_err(|e| format!("telegram send failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("telegram rejected: {}", res.status()));
        }
        Ok(())
    }

    /// Open (or reuse) a Discord DM channel, then push approve/deny buttons.
    pub async fn discord_qr_push(&self, discord_user_id: &str, challenge_id: &str) -> Result<(), String> {
        let token = Self::dc_token().ok_or("discord not configured")?;
        let ch: serde_json::Value = self
            .http
            .post("https://discord.com/api/v10/users/@me/channels")
            .header("Authorization", format!("Bot {token}"))
            .json(&json!({ "recipient_id": discord_user_id }))
            .send()
            .await
            .map_err(|e| format!("discord dm failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("discord dm parse failed: {e}"))?;
        let channel_id = ch
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("discord dm rejected")?;
        let res = self
            .http
            .post(format!("https://discord.com/api/v10/channels/{channel_id}/messages"))
            .header("Authorization", format!("Bot {token}"))
            .json(&json!({
                "content": "Hyper sign-in requested. Approve?",
                "components": [{ "type": 1, "components": [
                    { "type": 2, "style": 3, "label": "Approve", "custom_id": format!("qr:ok:{challenge_id}") },
                    { "type": 2, "style": 4, "label": "Deny", "custom_id": format!("qr:no:{challenge_id}") },
                ]}],
            }))
            .send()
            .await
            .map_err(|e| format!("discord send failed: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("discord rejected: {}", res.status()));
        }
        Ok(())
    }

    /// Best-effort global /link command registration (runs at startup).
    pub async fn discord_register_commands(&self) {
        let (Some(token), Some(app_id)) = (
            Self::dc_token(),
            std::env::var("DISCORD_APP_ID").ok().filter(|s| !s.is_empty()),
        ) else {
            return;
        };
        let res = self
            .http
            .put(format!("https://discord.com/api/v10/applications/{app_id}/commands"))
            .header("Authorization", format!("Bot {token}"))
            .json(&json!([{
                "name": "link",
                "description": "Link this Discord account to Hyper with a code",
                "options": [{ "name": "code", "description": "Code from Hyper", "type": 3, "required": true }],
            }]))
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => tracing::info!("discord /link command registered"),
            Ok(r) => tracing::warn!("discord command register rejected: {}", r.status()),
            Err(e) => tracing::warn!("discord command register failed: {e}"),
        }
    }
}
