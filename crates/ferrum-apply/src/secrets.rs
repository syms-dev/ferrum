use std::path::Path;
use std::process::Command;

/// Servarr apps that get an auto-generated API key. qBittorrent has its own
/// WebUI username/password, Plex uses Plex.tv account auth, Jellyfin and
/// SABnzbd have their own first-run setup flows -- none of those four go
/// through this mechanism (see the design spec's Secrets section).
const SERVARR_APPS: &[&str] = &["sonarr", "radarr", "prowlarr"];

/// Derives the box's PUBLIC age recipient from its own SSH host key, via
/// ssh-to-age. Needs no privilege and touches no private key material --
/// this is the same derivation sops-nix's own decrypt side uses by default
/// (sops.age.sshKeyPaths), just run in the encrypt direction.
pub fn host_age_recipient() -> anyhow::Result<String> {
    let pubkey_path = "/etc/ssh/ssh_host_ed25519_key.pub";
    let pubkey = std::fs::read_to_string(pubkey_path).map_err(|e| {
        anyhow::anyhow!("failed to read SSH host public key at {pubkey_path}: {e}")
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
/// community convention for Sonarr/Radarr/Prowlarr API keys (no format is
/// enforced by the nixpkgs module itself, but this is what the apps
/// generate on their own first run, so ferrum's generated ones look
/// identical).
fn random_hex_key() -> anyhow::Result<String> {
    let bytes: [u8; 16] = rand_bytes()?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn rand_bytes() -> anyhow::Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| anyhow::anyhow!("failed to open /dev/urandom: {e}"))?;
    std::io::Read::read_exact(&mut f, &mut buf)
        .map_err(|e| anyhow::anyhow!("failed to read from /dev/urandom: {e}"))?;
    Ok(buf)
}

/// Encrypts `plaintext` with sops, using only the recipient's PUBLIC age
/// key, and writes it to `dest`. No private key is ever touched by this
/// process -- confirmed real behaviour of `sops --encrypt --age <recipient>`
/// (nix run nixpkgs#sops -- --help on ferrum-dev).
fn encrypt_and_write(plaintext: &str, recipient: &str, dest: &Path) -> anyhow::Result<()> {
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
    // to find.
    let tmp = dest.with_extension("sops.tmp");
    std::fs::write(&tmp, &output.stdout)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

/// Ensures every enabled servarr app in `apps` has a `<app>-apikey.sops`
/// file under `secrets_dir`, generating and encrypting a new random key for
/// any that don't have one yet. Idempotent: an app whose .sops file already
/// exists is left completely alone (its key is never regenerated or read
/// back -- this process has no way to decrypt it anyway).
pub fn ensure_all(secrets_dir: &Path, recipient: &str, apps: &[&str]) -> anyhow::Result<()> {
    for app in apps {
        if !SERVARR_APPS.contains(app) {
            continue;
        }
        let dest = secrets_dir.join(format!("{app}-apikey.sops"));
        if dest.exists() {
            continue;
        }
        let key = random_hex_key()?;
        let env_var = format!("{}__AUTH__APIKEY", app.to_uppercase());
        let content = format!("{env_var}={key}\n");
        encrypt_and_write(&content, recipient, &dest)?;
    }
    Ok(())
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
    fn ensure_all_only_touches_servarr_apps() {
        let dir = tempfile::tempdir().unwrap();
        // qbittorrent is not in SERVARR_APPS -- ensure_all must be a no-op
        // for it even though it's in the requested `apps` list. Uses a
        // fake recipient and expects sops to fail (no real sops binary
        // guaranteed in a plain `cargo test` sandbox) -- the assertion
        // that matters is that NO file was created for qbittorrent,
        // regardless of whether sonarr's encrypt call succeeded or failed
        // in this environment.
        let _ = ensure_all(dir.path(), "age1nonexistentrecipient", &["qbittorrent"]);
        assert!(!dir.path().join("qbittorrent-apikey.sops").exists());
    }
}
