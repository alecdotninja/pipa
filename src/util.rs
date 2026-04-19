//! Shared constants and helper utilities.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

/// The only remote port the relay will publish or route.
pub(crate) const SSH_PORT: u32 = 22;

/// Accepted port aliases for publisher remote forwarding.
pub(crate) const SSH_PORT_OR_ALIAS: [u32; 2] = [0, SSH_PORT];

/// Length of generated publish tokens.
pub(crate) const PUBLISH_TOKEN_LEN: usize = 12;

/// Normalizes a domain name for matching and lookups.
pub(crate) fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Converts a hostname into a fully-qualified domain name.
pub(crate) fn fqdn(hostname: &str) -> String {
    format!("{}.", normalize_domain(hostname))
}

/// Validates the relay's accepted hostname syntax.
pub(crate) fn hostname_syntax_allowed(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 253
        && hostname
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63 && label_bytes_allowed(label))
}

/// Validates a single DNS label.
pub(crate) fn label_bytes_allowed(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        && bytes.first() != Some(&b'-')
        && bytes.last() != Some(&b'-')
}

/// Generates a random hostname label for registrations.
pub(crate) fn random_label() -> String {
    random_base32(10)
}

/// Generates a random publish token.
pub(crate) fn random_token() -> String {
    random_base32(PUBLISH_TOKEN_LEN)
}

/// Generates a lowercase base32 token of the requested length.
pub(crate) fn random_base32(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char)
        .collect()
}

/// Returns the publisher token when the SSH username matches the token syntax.
pub(crate) fn publish_token_from_user(user: &str) -> Option<&str> {
    valid_publish_token(user).then_some(user)
}

/// Validates publisher token syntax.
pub(crate) fn valid_publish_token(token: &str) -> bool {
    token.len() == PUBLISH_TOKEN_LEN
        && token
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
}

/// Hashes a publish token for persistent storage.
pub(crate) fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

/// Normalizes outgoing text for PTY-backed SSH sessions.
pub(crate) fn to_crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                out.push('\r');
                if matches!(chars.peek(), Some('\n')) {
                    out.push(chars.next().unwrap());
                }
            }
            '\n' => out.push_str("\r\n"),
            _ => out.push(ch),
        }
    }
    out
}
