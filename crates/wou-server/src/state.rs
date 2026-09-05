use std::sync::Arc;
use wou_crypto::{JwtManager, OAuthManager};
use wou_mail::StalwartMailer;
use wou_storage::WouStorage;

use crate::bots::BotClients;

#[derive(Clone)]
pub struct AppState {
    pub storage: WouStorage,
    pub mailer: StalwartMailer,
    pub jwt: Arc<JwtManager>,
    pub oauth: Arc<OAuthManager>,
    pub bots: Arc<BotClients>,
    pub otp_expiry_seconds: u64,
    /// Ops inbox for abuse alerts (None = log-only). Env `WOU_ADMIN_ALERT_EMAIL`.
    pub admin_alert_email: Option<String>,
}
