use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use wou_core::{GameContext, WouError};

use crate::templates::{render_admin_alert, render_otp_email, render_welcome_email};
use crate::templates::EmailContent;

#[derive(Clone, Debug)]
pub struct StalwartMailerConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub domain_passwords: HashMap<String, String>,
}

#[derive(Clone)]
pub struct StalwartMailer {
    _host: String,
    _port: u16,
    transports: Arc<HashMap<String, AsyncSmtpTransport<Tokio1Executor>>>,
    default_transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl StalwartMailer {
    pub fn new(config: StalwartMailerConfig) -> Result<Self, WouError> {
        let mut transports = HashMap::new();

        for (sender_email, password) in &config.domain_passwords {
            let creds = Credentials::new(sender_email.clone(), password.clone());
            let transport = if config.smtp_port == 465 {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                    .map_err(|e| WouError::MailError(format!("Failed to build SMTP relay for {sender_email}: {e}")))?
                    .credentials(creds)
                    .port(config.smtp_port)
                    .build()
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                    .map_err(|e| WouError::MailError(format!("Failed to build StartTLS relay for {sender_email}: {e}")))?
                    .credentials(creds)
                    .port(config.smtp_port)
                    .build()
            };
            transports.insert(sender_email.clone(), transport);
        }

        // Default fallback transport (worldofunreal.com). No hardcoded password:
        // missing env = refuse to build (open-source safe).
        let default_user = "no-reply@worldofunreal.com";
        let default_pass = config.domain_passwords.get(default_user).cloned().expect(
            "FATAL: WOU_SMTP_PASS_WORLDOFUNREAL must be set in environment",
        );

        let default_creds = Credentials::new(default_user.to_string(), default_pass);
        let default_transport = if config.smtp_port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                .map_err(|e| WouError::MailError(format!("Failed to build default relay: {e}")))?
                .credentials(default_creds)
                .port(config.smtp_port)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                .map_err(|e| WouError::MailError(format!("Failed to build default StartTLS relay: {e}")))?
                .credentials(default_creds)
                .port(config.smtp_port)
                .build()
        };

        info!(
            "StalwartMailer initialized for host {}:{} with {} sender transports",
            config.smtp_host,
            config.smtp_port,
            transports.len()
        );

        Ok(Self {
            _host: config.smtp_host,
            _port: config.smtp_port,
            transports: Arc::new(transports),
            default_transport,
        })
    }

    /// Dispatch a 6-digit OTP code to a player's email address with custom game branding.
    pub async fn send_otp(
        &self,
        recipient_email: &str,
        context: GameContext,
        code: &str,
        expires_in_minutes: u64,
    ) -> Result<(), WouError> {
        let sender_email = context.default_sender();
        let content = render_otp_email(context, code, expires_in_minutes);

        let from_header = format!("{} <{}>", context.display_name(), sender_email)
            .parse()
            .map_err(|e| WouError::MailError(format!("Invalid From address: {e}")))?;

        let to_header = recipient_email
            .parse()
            .map_err(|e| WouError::MailError(format!("Invalid To address: {e}")))?;

        let email = Message::builder()
            .from(from_header)
            .to(to_header)
            .subject(content.subject)
            .header(lettre::message::header::ContentType::TEXT_HTML)
            .body(content.html_body)
            .map_err(|e| WouError::MailError(format!("Failed to build email message: {e}")))?;

        let transport = self
            .transports
            .get(sender_email)
            .unwrap_or(&self.default_transport);

        transport
            .send(email)
            .await
            .map_err(|e| WouError::MailError(format!("SMTP delivery error: {e}")))?;

        info!(
            "OTP code successfully dispatched to {} from {} ({})",
            recipient_email,
            sender_email,
            context.display_name()
        );

        Ok(())
    }

    async fn dispatch(
        &self,
        to: &str,
        from_name: &str,
        from_email: &str,
        content: EmailContent,
    ) -> Result<(), WouError> {
        let from_header = format!("{from_name} <{from_email}>")
            .parse()
            .map_err(|e| WouError::MailError(format!("Invalid From address: {e}")))?;
        let to_header = to
            .parse()
            .map_err(|e| WouError::MailError(format!("Invalid To address: {e}")))?;
        let email = Message::builder()
            .from(from_header)
            .to(to_header)
            .subject(content.subject)
            .header(lettre::message::header::ContentType::TEXT_HTML)
            .body(content.html_body)
            .map_err(|e| WouError::MailError(format!("Failed to build email message: {e}")))?;
        let transport = self.transports.get(from_email).unwrap_or(&self.default_transport);
        transport
            .send(email)
            .await
            .map_err(|e| WouError::MailError(format!("SMTP delivery error: {e}")))?;
        Ok(())
    }

    /// One-time welcome for a newly created account. Best-effort: never fails auth.
    pub async fn send_welcome(
        &self,
        recipient_email: &str,
        context: GameContext,
        display_name: &str,
    ) -> Result<(), WouError> {
        let sender_email = context.default_sender();
        let content = render_welcome_email(context, display_name);
        self.dispatch(recipient_email, context.display_name(), sender_email, content)
            .await?;
        info!("Welcome dispatched to {recipient_email} ({})", context.display_name());
        Ok(())
    }

    /// Internal security alert to the ops inbox. Best-effort: never fails auth.
    pub async fn send_admin_alert(&self, to_admin: &str, subject: &str, body: &str) -> Result<(), WouError> {
        let sender_email = GameContext::WorldOfUnreal.default_sender();
        let content = render_admin_alert(subject, body);
        self.dispatch(to_admin, "WouID Security", sender_email, content)
            .await?;
        info!("Admin alert dispatched: {subject}");
        Ok(())
    }
}
