use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey as K256VerifyingKey};
use wou_core::WouError;

/// Verify an Ethereum / EVM Personal Sign message (EIP-191 / SIWE).
pub fn verify_ethereum_signature(
    expected_address: &str,
    message: &str,
    signature_hex: &str,
) -> Result<bool, WouError> {
    let clean_sig = signature_hex.trim_start_matches("0x");
    let sig_bytes = hex::decode(clean_sig)
        .map_err(|e| WouError::InvalidSignature("ethereum".into(), format!("Hex decode failed: {e}")))?;

    if sig_bytes.len() != 65 {
        return Err(WouError::InvalidSignature(
            "ethereum".into(),
            "Signature must be exactly 65 bytes".into(),
        ));
    }

    let r_s_bytes = &sig_bytes[0..64];
    let v = sig_bytes[64];

    // Standard Ethereum v values (27, 28 or 0, 1)
    let recid_byte = if v >= 27 { v - 27 } else { v };
    let recid = RecoveryId::from_byte(recid_byte)
        .ok_or_else(|| WouError::InvalidSignature("ethereum".into(), "Invalid recovery ID".into()))?;

    let signature = K256Signature::from_slice(r_s_bytes)
        .map_err(|e| WouError::InvalidSignature("ethereum".into(), format!("Invalid signature format: {e}")))?;

    // EIP-191 Prefix: "\x19Ethereum Signed Message:\n" + len + message
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = sha2::Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();

    let recovered_key = K256VerifyingKey::recover_from_prehash(&hash, &signature, recid)
        .map_err(|e| WouError::InvalidSignature("ethereum".into(), format!("Recovery failed: {e}")))?;

    // Derive Ethereum Address: Last 20 bytes of Keccak-256 of uncompressed public key (64 bytes, skipping 0x04)
    let encoded_point = recovered_key.to_encoded_point(false);
    let pubkey_bytes = &encoded_point.as_bytes()[1..]; // 64 bytes
    
    // Keccak256 hash
    use sha3::Digest as Sha3Digest;
    use sha3::Keccak256;
    let mut keccak = Keccak256::new();
    keccak.update(pubkey_bytes);
    let address_hash = keccak.finalize();
    let derived_address = format!("0x{}", hex::encode(&address_hash[12..32]));

    Ok(derived_address.eq_ignore_ascii_case(expected_address))
}

/// Verify a Solana Ed25519 Wallet signature (SIWS).
pub fn verify_solana_signature(
    pubkey_base58: &str,
    message: &str,
    signature_base58: &str,
) -> Result<bool, WouError> {
    let pubkey_bytes = bs58::decode(pubkey_base58)
        .into_vec()
        .map_err(|e| WouError::InvalidSignature("solana".into(), format!("Invalid pubkey base58: {e}")))?;

    let sig_bytes = bs58::decode(signature_base58)
        .into_vec()
        .map_err(|e| WouError::InvalidSignature("solana".into(), format!("Invalid signature base58: {e}")))?;

    if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
        return Err(WouError::InvalidSignature(
            "solana".into(),
            "Invalid key/signature length".into(),
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
