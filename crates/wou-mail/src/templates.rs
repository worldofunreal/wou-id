use wou_core::GameContext;

pub struct EmailContent {
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}
/// Generate Branded HTML & Plaintext Template for OTP Verification Code.
pub fn render_otp_email(context: GameContext, code: &str, expires_in_minutes: u64) -> EmailContent {
    let game_name = context.display_name();
    let theme_color = match context {
        GameContext::ShadowsOfWar => "#e11d48", // Crimson / Red
        GameContext::Cosmicrafts => "#0284c7",  // Sci-fi Cyan / Blue
        GameContext::Nftropoly => "#8b5cf6",    // Cyber Violet
        GameContext::Darkrift => "#10b981",     // AI Emerald
        GameContext::WorldOfUnreal => "#f59e0b", // Gold
    };

    let subject = format!("🛡️ Your {game_name} Verification Code: {code}");

    let html_body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{subject}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; margin: 0; padding: 24px; color: #f8fafc; }}
    .container {{ max-width: 520px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; overflow: hidden; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    .header {{ background-color: #0f172a; padding: 24px; text-align: center; border-bottom: 2px solid {theme_color}; }}
    .header h1 {{ margin: 0; font-size: 20px; font-weight: 700; letter-spacing: 0.5px; color: #ffffff; }}
    .content {{ padding: 32px 24px; text-align: center; }}
    .title {{ font-size: 18px; font-weight: 600; margin-bottom: 12px; color: #f1f5f9; }}
    .subtitle {{ font-size: 14px; color: #94a3b8; line-height: 1.5; margin-bottom: 24px; }}
    .code-box {{ background-color: #0f172a; border: 2px dashed {theme_color}; border-radius: 8px; padding: 18px; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #ffffff; margin: 0 auto 24px auto; display: inline-block; font-family: 'Courier New', Courier, monospace; }}
    .note {{ font-size: 12px; color: #64748b; margin-top: 16px; }}
    .footer {{ background-color: #0f172a; padding: 18px; text-align: center; font-size: 11px; color: #475569; border-top: 1px solid #334155; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>{game_name}</h1>
    </div>
    <div class="content">
      <div class="title">Verify Your Player Account</div>
      <div class="subtitle">Enter the 6-digit code below to link your email, save your game progress, and claim your rewards.</div>
      <div class="code-box">{code}</div>
      <div class="note">This code will expire in <strong>{expires_in_minutes} minutes</strong>. If you did not request this code, you can safely ignore this email.</div>
    </div>
    <div class="footer">
      Powered by World of Unreal Identity &bull; Security &bull; Zero Spam
    </div>
  </div>
</body>
</html>"#
    );

    let text_body = format!(
        "Your {game_name} verification code is: {code}\n\nThis code expires in {expires_in_minutes} minutes.\nIf you did not request this, you can safely ignore this message."
    );

    EmailContent {
        subject,
        html_body,
        text_body,
    }
}

/// One-time welcome email for a newly created account with a verified email.
/// Transactional (not marketing): sent once, idempotent via `welcome_sent`.
pub fn render_welcome_email(context: GameContext, display_name: &str) -> EmailContent {
    let game_name = context.display_name();
    let subject = format!("Welcome to {game_name} — your WouID account is ready");

    let html_body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{subject}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; margin: 0; padding: 24px; color: #f8fafc; }}
    .container {{ max-width: 520px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; overflow: hidden; border: 1px solid #334155; }}
    .header {{ background-color: #0f172a; padding: 24px; text-align: center; }}
    .header h1 {{ margin: 0; font-size: 20px; font-weight: 700; color: #ffffff; }}
    .content {{ padding: 32px 24px; font-size: 14px; color: #cbd5e1; line-height: 1.6; }}
    .content a {{ color: #38bdf8; }}
    .footer {{ background-color: #0f172a; padding: 18px; text-align: center; font-size: 11px; color: #475569; border-top: 1px solid #334155; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>{game_name}</h1>
    </div>
    <div class="content">
      <p>Hi {display_name},</p>
      <p>Your WouID player account was created from {game_name}. One identity for every World of Unreal game: progress, items and linked wallets travel with you.</p>
      <p>Manage your profile and linked accounts at <a href="https://worldofunreal.com">worldofunreal.com</a>.</p>
      <p>This is a one-time message. Security questions: reply to <a href="mailto:security@worldofunreal.com">security@worldofunreal.com</a>.</p>
    </div>
    <div class="footer">
      World of Unreal Identity &bull; transactional message, no subscription
    </div>
  </div>
</body>
</html>"#
    );

    let text_body = format!(
        "Hi {display_name},\n\nYour WouID player account was created from {game_name}. One identity for every World of Unreal game.\n\nManage your profile at https://worldofunreal.com\nSecurity questions: security@worldofunreal.com\n\nThis is a one-time message."
    );

    EmailContent {
        subject,
        html_body,
        text_body,
    }
}

/// Internal security alert (abuse bans, blocks, protection mode). Never user-facing.
pub fn render_admin_alert(subject: &str, body: &str) -> EmailContent {
    EmailContent {
        subject: format!("[WOU-ALERT] {subject}"),
        html_body: format!(
            "<pre style=\"font-family:monospace\">{}</pre>",
            body.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        ),
        text_body: body.to_string(),
    }
}
