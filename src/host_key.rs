//! SSH host key loading and generation.

use std::path::Path;

use anyhow::{Context, Result};
use rand_core::OsRng;
use russh::keys::{ssh_key, Algorithm, PrivateKey};
use tracing::info;

/// Loads the SSH host key from disk or generates one when missing.
pub(crate) fn load_or_generate_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        let key = PrivateKey::read_openssh_file(path)
            .with_context(|| format!("reading SSH host key {}", path.display()))?;
        info!(path = %path.display(), "loaded SSH host key");
        return Ok(key);
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating SSH host key directory {}", parent.display()))?;
    }

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    key.write_openssh_file(path, ssh_key::LineEnding::LF)
        .with_context(|| format!("writing SSH host key {}", path.display()))?;
    info!(path = %path.display(), "generated SSH host key");
    Ok(key)
}
