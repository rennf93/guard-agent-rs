//! HMAC-SHA256 request signing for the `X-Payload-Signature` header.
//!
//! The signature covers the *uncompressed* JSON body. The ingestion API
//! verifies the signature against the request body after its gzip middleware
//! has decompressed it
//! (`guard-core-api/guard_core_api/api/routers/telemetry_router.py:113` runs
//! after `core/gzip_request_middleware.py:46` rewrites the body), so signing
//! the pre-compression bytes is the only form the server can validate. The
//! Python and TypeScript agents sign the post-gzip wire bytes instead, which
//! fails verification whenever compression is active; this crate deliberately
//! signs the plaintext body and documents the difference.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use std::fmt::Write as _;

/// Prefix carried by every signature value.
pub const SIGNATURE_PREFIX: &str = "v1=";

/// Signs `body` with `secret`, returning `v1=<hex>`.
///
/// Returns `None` when no secret is configured, in which case the header is
/// omitted entirely (matching the Python and TypeScript agents).
#[must_use]
pub fn sign_payload(body: &[u8], secret: Option<&str>) -> Option<String> {
    let secret = secret?;
    // `Hmac::new_from_slice` accepts keys of any length for SHA-256, so this
    // cannot fail; the expect documents that invariant instead of unwrapping.
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(SIGNATURE_PREFIX.len() + digest.len() * 2);
    hex.push_str(SIGNATURE_PREFIX);
    for byte in digest {
        // Writing into a `String` never fails.
        let _ = write!(hex, "{byte:02x}");
    }
    Some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_a_known_vector() {
        // Vector computed with Python: hmac.new(b"test-secret", b"hello-body",
        // hashlib.sha256).hexdigest()
        let signature = sign_payload(b"hello-body", Some("test-secret")).unwrap();
        assert_eq!(
            signature,
            "v1=165917413384af8ebc4d8125fa3fa3ce7ff13713a6a6188a0ec9a418fcccb3b9"
        );
    }

    #[test]
    fn signature_handles_empty_body() {
        let signature = sign_payload(b"", Some("secret")).unwrap();
        assert_eq!(
            signature,
            "v1=f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169"
        );
    }

    #[test]
    fn no_secret_means_no_header() {
        assert!(sign_payload(b"payload", None).is_none());
    }

    #[test]
    fn signature_is_lowercase_hex_with_prefix() {
        let signature = sign_payload(b"payload", Some("secret")).unwrap();
        assert!(signature.starts_with(SIGNATURE_PREFIX));
        let hex = &signature[SIGNATURE_PREFIX.len()..];
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn different_secrets_produce_different_signatures() {
        let first = sign_payload(b"payload", Some("a")).unwrap();
        let second = sign_payload(b"payload", Some("b")).unwrap();
        assert_ne!(first, second);
    }
}
