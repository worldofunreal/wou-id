pub mod crazygames;
pub mod jwt;
pub mod oauth;
pub mod otp;
pub mod web3;

pub use crazygames::verify_crazygames_token;
pub use jwt::JwtManager;
pub use oauth::{OAuthManager, OAuthUserInfo};
pub use otp::generate_secure_otp;
pub use web3::{verify_ethereum_signature, verify_solana_signature};
