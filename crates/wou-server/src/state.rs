use std::sync::Arc;
use wou_crypto::{JwtManager, OAuthManager};
use wou_mail::StalwartMailer;
use wou_storage::WouStorage;

#[derive(Clone)]
pub struct AppState {
    pub storage: WouStorage,
    pub mailer: StalwartMailer,
    pub jwt: Arc<JwtManager>,
    pub oauth: Arc<OAuthManager>,
    pub otp_expiry_seconds: u64,
}
