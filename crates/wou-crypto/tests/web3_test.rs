use ed25519_dalek::{Signer, SigningKey};
use wou_crypto::verify_solana_signature;

#[test]
fn test_solana_signature_verification() {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let message = "Sign in to World of Unreal ID with Solana: nonce=981247";
    let signature = signing_key.sign(message.as_bytes());

    let pubkey_base58 = bs58::encode(verifying_key.as_bytes()).into_string();
    let signature_base58 = bs58::encode(signature.to_bytes()).into_string();

    let result = verify_solana_signature(&pubkey_base58, message, &signature_base58).unwrap();
    assert!(result, "Valid Solana signature should verify as true");

    let tampered_result =
        verify_solana_signature(&pubkey_base58, "tampered message", &signature_base58).unwrap();
    assert!(!tampered_result, "Tampered message should fail verification");
}
