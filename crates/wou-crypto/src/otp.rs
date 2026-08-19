use rand::Rng;

/// Generate a cryptographically secure 6-digit numeric OTP (e.g., "582914").
pub fn generate_secure_otp() -> String {
    let mut rng = rand::thread_rng();
    let num: u32 = rng.gen_range(100_000..=999_999);
    num.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otp_length_and_range() {
        for _ in 0..100 {
            let code = generate_secure_otp();
            assert_eq!(code.len(), 6);
            let val: u32 = code.parse().unwrap();
            assert!(val >= 100_000 && val <= 999_999);
        }
    }
}
