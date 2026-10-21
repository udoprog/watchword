use std::string::String;
use std::sync::LazyLock;

/// Hashing a password failed.
#[derive(Debug, thiserror::Error)]
#[error("failed to hash password")]
pub struct PasswordError(#[source] bcrypt::BcryptError);

/// Hashes with bcrypt at its default cost, which keeps hashes interchangeable
/// with other bcrypt implementations.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(PasswordError)
}

/// Hashes at bcrypt's lowest cost, which is quick to hash and to check, for
/// test users.
#[cfg(any(test, feature = "test-util"))]
pub(crate) fn hash_password_cheaply(password: &str) -> Result<String, PasswordError> {
    bcrypt::hash(password, 4).map_err(PasswordError)
}

/// A malformed hash verifies as false.
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// A hash of a random password, to verify against when there is no real hash
/// so that a missing account takes as long as a wrong password.
pub fn dummy_hash() -> &'static str {
    static HASH: LazyLock<String> = LazyLock::new(|| {
        let password: [u8; 16] = rand::random();
        bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("hashing a random password")
    });

    &HASH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_round_trip() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong horse", &hash));
        assert!(!verify_password("correct horse", "not a hash"));
        assert!(!verify_password("", dummy_hash()));
    }
}
