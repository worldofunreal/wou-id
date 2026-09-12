use axum::http::HeaderMap;

use crate::state::AppState;

/// Client IP from OUR nginx (the server only listens on loopback, so
/// X-Real-IP cannot be spoofed from outside). IPv6 is reduced to its /64
/// prefix (one end-site, one bucket). Falls back to "local".
pub fn client_ip(headers: &HeaderMap) -> String {
    let raw = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".to_string());
    match raw.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        _ => raw,
    }
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

/// Ownership proof for link/merge flows: the caller must present a valid JWT
/// whose subject IS the target account. A client-supplied `account_id` alone
/// is never trusted (it used to mint sessions for arbitrary accounts).
pub async fn verified_owner(
    headers: &HeaderMap,
    state: &AppState,
    target_id: &str,
) -> bool {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .map(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
                .unwrap_or(h)
                .trim()
        })
        .unwrap_or("");
    if token.is_empty() {
        return false;
    }
    match state.jwt.verify_token(token) {
        Ok(claims) => claims.sub == target_id,
        Err(_) => false,
    }
}

/// Short de-identified tag for logs (no PII on disk).
pub fn log_tag(email: &str) -> String {
    wou_core::key_tag(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_ip_v4_local_v6() {
        let mut h = HeaderMap::new();
        assert_eq!(client_ip(&h), "local");
        h.insert("x-real-ip", "203.0.113.7".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.7");
        h.insert(
            "x-real-ip",
            "2806:2f0:5240:fc65:216:ebff:fe87:ff41".parse().unwrap(),
        );
        assert_eq!(client_ip(&h), "2806:2f0:5240:fc65::/64");
    }
}
