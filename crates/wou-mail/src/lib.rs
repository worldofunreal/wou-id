pub mod mailer;
pub mod templates;

pub use mailer::{StalwartMailer, StalwartMailerConfig};
pub use templates::{render_otp_email, EmailContent};
