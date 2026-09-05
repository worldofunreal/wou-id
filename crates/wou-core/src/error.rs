use thiserror::Error;

#[derive(Error, Debug)]
pub enum WouError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Email already linked to another account: {0}")]
    EmailAlreadyLinked(String),

    #[error("Invalid or expired OTP code")]
    InvalidOrExpiredOtp,

    #[error("Rate limit exceeded: please wait {0} seconds before requesting a new code")]
    RateLimitExceeded(u64),

    #[error("Too many codes requested: please wait {0} seconds")]
    OtpThrottled(u64),

    #[error("Abuse detected: please wait {0} seconds before trying again")]
    OtpPenalized(u64),

    #[error("This address is banned for abuse. Appeal at security@worldofunreal.com")]
    EmailBanned,

    #[error("Blocked for 24 hours due to abuse")]
    IpBlocked,

    #[error("Invalid email address: {0}")]
    InvalidEmail(String),

    #[error("Invalid signature for provider {0}: {1}")]
    InvalidSignature(String, String),

    #[error("Provider verification failed: {0}")]
    ProviderVerificationFailed(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Mail dispatch error: {0}")]
    MailError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}
