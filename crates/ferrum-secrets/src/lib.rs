//! Zero-privilege secret-encryption primitives shared between
//! `ferrum-apply` (which uses them to auto-generate servarr/Authelia/
//! SABnzbd secrets) and `ferrumd` (which uses them to encrypt
//! operator-provided secrets from the API). Every function here needs
//! only the host's PUBLIC age recipient -- none of them ever touch a
//! private key, which is exactly what makes both callers' "write-only
//! secrets" property real rather than a policy someone has to remember
//! to uphold.
use std::path::Path;
use std::process::Command;

/// Default SSH host public key path, used only when a caller's own
/// environment override isn't set (e.g. under `cargo run` outside a built
/// wrapper). See `modules/core/overlays.nix`'s `FERRUM_HOST_KEY_PUB`
/// wiring for the real production value.
pub const DEFAULT_HOST_KEY_PUB: &str = "/etc/ssh/ssh_host_ed25519_key.pub";

/// Derives the box's PUBLIC age recipient from its own SSH host key, via
/// ssh-to-age. Needs no privilege and touches no private key material --
/// this is the same derivation sops-nix's own decrypt side uses by default
/// (sops.age.sshKeyPaths), just run in the encrypt direction. `pubkey_path`
/// should be the real path sops-nix's own config resolved to -- hardcoding
/// a default instead would silently desync from a host that overrides
/// services.openssh.hostKeys, encrypting to a recipient sops-nix never
/// decrypts with.
pub fn host_age_recipient(pubkey_path: &Path) -> anyhow::Result<String> {
    let pubkey = std::fs::read_to_string(pubkey_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read SSH host public key at {}: {e}",
            pubkey_path.display()
        )
    })?;

    let output = Command::new("ssh-to-age")
        .arg("-i")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin was piped")
                .write_all(pubkey.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| anyhow::anyhow!("failed to run ssh-to-age: {e}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "ssh-to-age failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// A cryptographically random 32-character hex string -- matches the
/// community convention for servarr API keys.
pub fn random_hex_key() -> anyhow::Result<String> {
    let bytes: [u8; 16] = rand_bytes()?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn rand_bytes() -> anyhow::Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| anyhow::anyhow!("failed to open /dev/urandom: {e}"))?;
    std::io::Read::read_exact(&mut f, &mut buf)
        .map_err(|e| anyhow::anyhow!("failed to read from /dev/urandom: {e}"))?;
    Ok(buf)
}

/// Encrypts `plaintext` with sops, using only the recipient's PUBLIC age
/// key, and writes it to `dest`. No private key is ever touched by this
/// process -- confirmed real behaviour of `sops --encrypt --age <recipient>`.
pub fn encrypt_and_write(plaintext: &str, recipient: &str, dest: &Path) -> anyhow::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let output = Command::new("sops")
        .args([
            "--encrypt",
            "--age",
            recipient,
            "--input-type",
            "binary",
            "--output-type",
            "binary",
            "/dev/stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .expect("stdin was piped")
                .write_all(plaintext.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| anyhow::anyhow!("failed to run sops --encrypt: {e}"))?;

    if !output.status.success() {
        anyhow::bail!(
            "sops --encrypt failed for {}: {}",
            dest.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // Write via a temp file + rename so a crash mid-write never leaves a
    // half-written .sops file for the next apply (or a curious operator)
    // to find. sync_all() before the rename matters as much as the rename
    // itself: without it, a power loss can land the rename durably while
    // the temp file's own content is still only in the page cache, leaving
    // a present-but-truncated .sops file that `dest.exists()` then treats
    // as valid forever.
    let tmp = dest.with_extension("sops.tmp");
    let file = std::fs::File::create(&tmp)?;
    {
        use std::io::Write;
        (&file).write_all(&output.stdout)?;
    }
    file.sync_all()?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

/// Cryptographically random bytes, base64-encoded -- Authelia's own docs
/// recommend a value "more than twenty characters"; 32 random bytes
/// (43 base64 characters) comfortably clears that with real entropy.
pub fn random_secret_value() -> anyhow::Result<String> {
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| anyhow::anyhow!("failed to open /dev/urandom: {e}"))?;
    std::io::Read::read_exact(&mut f, &mut buf)
        .map_err(|e| anyhow::anyhow!("failed to read from /dev/urandom: {e}"))?;
    Ok(base64_encode(&buf))
}

pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_hex_key_is_32_lowercase_hex_chars() {
        let key = random_hex_key().unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn random_hex_key_is_not_constant() {
        let a = random_hex_key().unwrap();
        let b = random_hex_key().unwrap();
        assert_ne!(a, b, "two calls produced the same key -- /dev/urandom read is broken");
    }

    #[test]
    fn base64_encode_matches_rfc_4648_test_vector() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
    }

    #[test]
    fn random_secret_value_is_real_entropy_not_constant() {
        let a = random_secret_value().unwrap();
        let b = random_secret_value().unwrap();
        assert_ne!(a, b);
        assert!(a.len() >= 20, "Authelia's own docs recommend more than 20 characters");
    }
}
