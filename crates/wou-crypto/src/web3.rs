use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use sha3::{Digest as Sha3Digest, Keccak256};
use wou_core::WouError;

/// Verify an Ethereum / EVM Personal Sign message (EIP-191 / SIWE).
pub fn verify_ethereum_signature(
    expected_address: &str,
    message: &str,
    signature_hex: &str,
) -> Result<bool, WouError> {
    let clean_sig = signature_hex.trim().trim_start_matches("0x");
    let sig_bytes = hex::decode(clean_sig)
        .map_err(|e| WouError::InvalidSignature("ethereum".into(), format!("Hex decode failed: {e}")))?;

    if sig_bytes.len() != 65 {
        return Err(WouError::InvalidSignature(
            "ethereum".into(),
            format!("Signature must be exactly 65 bytes, got {}", sig_bytes.len()),
        ));
    }

    let r_s_bytes = &sig_bytes[0..64];
    let v = sig_bytes[64];

    // Standard Ethereum v values (27, 28 or 0, 1 or EIP-155 offsets)
    let recid_byte = if v >= 27 {
        (v - 27) % 2
    } else {
        v % 2
    };

    let recid = RecoveryId::from_byte(recid_byte)
        .ok_or_else(|| WouError::InvalidSignature("ethereum".into(), "Invalid recovery ID".into()))?;

    let signature = K256Signature::from_slice(r_s_bytes)
        .map_err(|e| WouError::InvalidSignature("ethereum".into(), format!("Invalid signature format: {e}")))?;

    // EIP-191 Prefix: "\x19Ethereum Signed Message:\n" + len + message
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut keccak = Keccak256::new();
    keccak.update(prefix.as_bytes());
    keccak.update(message.as_bytes());
    let hash = keccak.finalize();

    let recovered_key = K256VerifyingKey::recover_from_prehash(&hash, &signature, recid)
        .map_err(|e| WouError::InvalidSignature("ethereum".into(), format!("Recovery failed: {e}")))?;

    // Derive Ethereum Address: Last 20 bytes of Keccak-256 of uncompressed public key (64 bytes, skipping 0x04)
    let encoded_point = recovered_key.to_encoded_point(false);
    let pubkey_bytes = &encoded_point.as_bytes()[1..]; // 64 bytes
    
    let mut addr_keccak = Keccak256::new();
    addr_keccak.update(pubkey_bytes);
    let address_hash = addr_keccak.finalize();
    let derived_address = format!("0x{}", hex::encode(&address_hash[12..32]));

    Ok(derived_address.eq_ignore_ascii_case(expected_address.trim()))
}

/// Verify a Solana Ed25519 Wallet signature (SIWS).
/// Accepts signature in both Base58 (Phantom native standard) and Hex (0x...) formats.
pub fn verify_solana_signature(
    pubkey_base58: &str,
    message: &str,
    signature_input: &str,
) -> Result<bool, WouError> {
    let clean_pk = pubkey_base58.trim();
    let pubkey_bytes = bs58::decode(clean_pk)
        .into_vec()
        .map_err(|e| WouError::InvalidSignature("solana".into(), format!("Invalid pubkey base58: {e}")))?;

    if pubkey_bytes.len() != 32 {
        return Err(WouError::InvalidSignature(
            "solana".into(),
            format!("Invalid Solana pubkey length (expected 32 bytes, got {})", pubkey_bytes.len()),
        ));
    }

    let clean_sig = signature_input.trim();
    let sig_bytes = if clean_sig.starts_with("0x") || (clean_sig.len() == 128 && clean_sig.chars().all(|c| c.is_ascii_hexdigit())) {
        let hex_str = clean_sig.trim_start_matches("0x");
        hex::decode(hex_str).map_err(|e| WouError::InvalidSignature("solana".into(), format!("Hex decode failed: {e}")))?
    } else {
        bs58::decode(clean_sig)
            .into_vec()
            .map_err(|e| WouError::InvalidSignature("solana".into(), format!("Base58 decode failed: {e}")))?
    };

    if sig_bytes.len() != 64 {
        return Err(WouError::InvalidSignature(
            "solana".into(),
            format!("Invalid Solana signature length (expected 64 bytes, got {})", sig_bytes.len()),
        ));
    }

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| WouError::InvalidSignature("solana".into(), format!("Invalid verifying key: {e}")))?;

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Validate ICP / Internet Identity Principal format (e.g. `2vxsx-fae` or `aaaaa-aa`).
pub fn validate_icp_principal(principal_text: &str) -> Result<bool, WouError> {
    let clean = principal_text.trim();
    if clean.is_empty() || clean.len() > 64 {
        return Ok(false);
    }
    // Standard ICP principal text format uses lowercase alphanumeric + hyphens
    let is_valid = clean.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    Ok(is_valid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    #[test]
    fn test_solana_signature_base58_and_hex() {
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_base58 = bs58::encode(verifying_key.as_bytes()).into_string();

        let message = "Sign this message to authenticate with World of Unreal Identity Engine.";
        let signature: Signature = signing_key.sign(message.as_bytes());

        // Test Base58 encoding
        let sig_base58 = bs58::encode(signature.to_bytes()).into_string();
        let result_b58 = verify_solana_signature(&pubkey_base58, message, &sig_base58);
        assert!(result_b58.is_ok());
        assert!(result_b58.unwrap());

        // Test Hex encoding
        let sig_hex = format!("0x{}", hex::encode(signature.to_bytes()));
        let result_hex = verify_solana_signature(&pubkey_base58, message, &sig_hex);
        assert!(result_hex.is_ok());
        assert!(result_hex.unwrap());
    }

    #[test]
    fn test_ethereum_eip191_signature_verification() {
        use k256::ecdsa::SigningKey;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        let encoded_point = verifying_key.to_encoded_point(false);
        let mut addr_keccak = Keccak256::new();
        addr_keccak.update(&encoded_point.as_bytes()[1..]);
        let address_hash = addr_keccak.finalize();
        let expected_address = format!("0x{}", hex::encode(&address_hash[12..32]));

        let message = "Test Ethereum personal sign message";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut msg_keccak = Keccak256::new();
        msg_keccak.update(prefix.as_bytes());
        msg_keccak.update(message.as_bytes());
        let hash = msg_keccak.finalize();

        let (signature, recid) = signing_key.sign_prehash_recoverable(&hash).unwrap();
        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&signature.to_bytes());
        sig_bytes.push(recid.to_byte() + 27);
        let sig_hex = format!("0x{}", hex::encode(&sig_bytes));

        let is_valid = verify_ethereum_signature(&expected_address, message, &sig_hex).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_validate_icp_principal() {
        assert!(validate_icp_principal("2vxsx-fae").unwrap());
        assert!(validate_icp_principal("aaaaa-aa").unwrap());
        assert!(validate_icp_principal("yrm6q-yyaaa-aaaap-qb6ka-cai").unwrap());
        assert!(!validate_icp_principal("Invalid Principal!@#").unwrap());
    }
}
