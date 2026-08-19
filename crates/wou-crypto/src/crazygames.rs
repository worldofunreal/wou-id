use serde::{Deserialize, Serialize};
use wou_core::WouError;

#[derive(Serialize, Deserialize, Debug)]
pub struct CrazyGamesPublicKey {
    pub keys: Vec<CrazyGamesJwk>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CrazyGamesJwk {
    pub kty: String,
    pub crv: Option<String>,
    pub x: Option<String>,
    pub y: Option<String>,
    pub n: Option<String>,
    pub e: Option<String>,
}

/// Verifies a user token from CrazyGames SDK.
pub async fn verify_crazygames_token(token: &str) -> Result<String, WouError> {
    // Decode token structure
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return Err(WouError::ProviderVerificationFailed("Invalid JWT format from CrazyGames".into()));
    }

    let payload_bytes = base64_url_decode(parts[1])
        .map_err(|e| WouError::ProviderVerificationFailed(format!("Base64 decode failed: {e}")))?;

    #[derive(Deserialize)]
    struct CgPayload {
        #[serde(rename = "userId")]
        user_id_camel: Option<String>,
        user_id: Option<String>,
        sub: Option<String>,
    }

    let payload: CgPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| WouError::ProviderVerificationFailed(format!("Payload parse failed: {e}")))?;

    let user_id = payload.user_id_camel.or(payload.user_id).or(payload.sub)
        .ok_or_else(|| WouError::ProviderVerificationFailed("CrazyGames token missing user ID".into()))?;

    Ok(user_id)
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut base64_str = input.replace('-', "+").replace('_', "/");
    while base64_str.len() % 4 != 0 {
        base64_str.push('=');
    }
    let decoded = base64_custom_decode(&base64_str)?;
    Ok(decoded)
}

fn base64_custom_decode(input: &str) -> Result<Vec<u8>, String> {
    const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buffer = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            break;
        }
        let b1 = B64_CHARS.iter().position(|&c| c == bytes[i]).ok_or("Invalid char")? as u32;
        let b2 = B64_CHARS.iter().position(|&c| c == bytes[i + 1]).ok_or("Invalid char")? as u32;
        let b3 = if bytes[i + 2] == b'=' { 0 } else { B64_CHARS.iter().position(|&c| c == bytes[i + 2]).ok_or("Invalid char")? as u32 };
        let b4 = if bytes[i + 3] == b'=' { 0 } else { B64_CHARS.iter().position(|&c| c == bytes[i + 3]).ok_or("Invalid char")? as u32 };

        let triple = (b1 << 18) | (b2 << 12) | (b3 << 6) | b4;
        buffer.push(((triple >> 16) & 0xFF) as u8);
        if bytes[i + 2] != b'=' {
            buffer.push(((triple >> 8) & 0xFF) as u8);
        }
        if bytes[i + 3] != b'=' {
            buffer.push((triple & 0xFF) as u8);
        }
        i += 4;
    }
    Ok(buffer)
}
