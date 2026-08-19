use lettre::message::{header::ContentType, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{error, info};
use wou_core::{GameContext, WouError};

use crate::templates::render_otp_email;

#[derive(Clone)]
pub struct StalwartMailerConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
}

#[derive(Clone)]
pub struct StalwartMailer {
    _config: StalwartMailerConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl StalwartMailer {
    pub fn new(config: StalwartMailerConfig) -> Result<Self, WouError> {
        let creds = Credentials::new(config.smtp_user.clone(), config.smtp_password.clone());

        // Connect via SMTPS (Port 465) or STARTTLS
        let transport = if config.smtp_port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                .map_err(|e| WouError::MailError(format!("Failed to build SMTP relay: {e}")))?
                .credentials(creds)
                .port(config.smtp_port)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                .map_err(|e| WouError::MailError(format!("Failed to build StartTLS relay: {e}")))?
                .credentials(creds)
                .port(config.smtp_port)
                .build()
        };

        info!("StalwartMailer initialized for host {}:{}", config.smtp_host, config.smtp_port);

        Ok(Self { _config: config, transport })
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
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(content.text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(content.html_body),
                    ),
            )
            .map_err(|e| WouError::MailError(format!("Failed to construct email: {e}")))?;

        match self.transport.send(email).await {
            Ok(response) => {
                info!(
                    "Successfully dispatched OTP email to {} via Stalwart (Code: {:?})",
                    recipient_email, response
                );
                Ok(())
            }
            Err(e) => {
                error!("Failed to dispatch OTP email to {}: {e}", recipient_email);
                Err(WouError::MailError(format!("SMTP delivery error: {e}")))
            }
        }
    }
}
