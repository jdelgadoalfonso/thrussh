use sha2::Sha256;
use hmac::{Hmac, Mac};

// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// The name of the hmac-sha2-512 algorithm for SSH.
pub const HMAC_SHA2_256: Name = Name("hmac-sha2-256");

