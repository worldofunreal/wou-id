use axum::http::HeaderMap;

use crate::state::AppState;

/// Client IP from OUR nginx (the server only listens on loopback, so
/// X-Real-IP cannot be spoofed from outside). Falls back to "local".
pub fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".to_string())
}

/// Best-effort abuse alert: spawned, never blocks or fails the request path.
pub fn fire_admin_alert(state: &AppState, subject: &str, body: String) {
    if let Some(to) = state.admin_alert_email.clone() {
        let mailer = state.mailer.clone();
        let subject = subject.to_string();
        tokio::spawn(async move {
            let _ = mailer.send_admin_alert(&to, &subject, &body).await;
        });
    }
}

/// Alert at most once per key per day (prevents alert spam during attacks).
pub async fn fire_admin_alert_once(state: &AppState, key: &str, subject: &str, body: String) {
    match state.storage.check_rate(&format!("wou_alert:{key}"), 86400).await {
        Ok(true) => fire_admin_alert(state, subject, body),
        _ => {}
    }
}

/// Short de-identified tag for logs (no PII on disk).
pub fn log_tag(email: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    email.to_lowercase().hash(&mut h);
    format!("{:016x}", h.finish())[..12].to_string()
}
