use std::path::Path;
use std::process::Command;

/// Servarr apps that get an auto-generated API key. qBittorrent has its own
/// WebUI username/password, Plex uses Plex.tv account auth, Jellyfin and
/// SABnzbd have their own first-run setup flows -- none of those four go
/// through this mechanism (see the design spec's Secrets section).
const SERVARR_APPS: &[&str] = &["sonarr", "radarr", "prowlarr"];

/// Default SSH host public key path, used only when the wrapper's
/// FERRUM_HOST_KEY_PUB (derived from this host's real
/// config.sops.age.sshKeyPaths -- see modules/core/overlays.nix) isn't set,
/// e.g. under `cargo run` outside a built ferrum-apply wrapper.
pub const DEFAULT_HOST_KEY_PUB: &str = "/etc/ssh/ssh_host_ed25519_key.pub";

/// Derives the box's PUBLIC age recipient from its own SSH host key, via
/// ssh-to-age. Needs no privilege and touches no private key material --
/// this is the same derivation sops-nix's own decrypt side uses by default
/// (sops.age.sshKeyPaths), just run in the encrypt direction. `pubkey_path`
/// should be the real path sops-nix's own config resolved to (passed by the
/// caller from FERRUM_HOST_KEY_PUB) -- hardcoding the default here instead
/// would silently desync from a host that overrides
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
    // to find. sync_all() before the rename matters as much as the rename
    // itself: without it, a power loss can land the rename durably while
    // the temp file's own content is still only in the page cache, leaving
    // a present-but-truncated .sops file that `dest.exists()` then treats
    // as valid forever (ensure_all never reads a secret back to check it).
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

/// Ensures every enabled servarr app in `apps` has a `<app>-apikey.sops`
/// file under `secrets_dir`, generating and encrypting a new random key for
/// any that don't have one yet. Idempotent: an app whose .sops file already
/// exists is left completely alone (its key is never regenerated or read
/// back -- this process has no way to decrypt it anyway).
///
/// `pubkey_path` is only actually read (via ssh-to-age, which needs no
/// privilege) when at least one app is genuinely missing its .sops file --
/// a host with nothing to generate (every app's key already exists, or no
/// servarr apps enabled) never touches the SSH host key at all, so a
/// missing/unreadable host key can't break `ferrum-apply apply` on a host
/// that doesn't need this mechanism.
pub fn ensure_all(secrets_dir: &Path, pubkey_path: &Path, apps: &[&str]) -> anyhow::Result<()> {
    let missing: Vec<&str> = apps
        .iter()
        .copied()
        .filter(|app| SERVARR_APPS.contains(app))
        .filter(|app| !secrets_dir.join(format!("{app}-apikey.sops")).exists())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let recipient = host_age_recipient(pubkey_path)?;
    for app in missing {
        let dest = secrets_dir.join(format!("{app}-apikey.sops"));
        let key = random_hex_key()?;
        let env_var = format!("{}__AUTH__APIKEY", app.to_uppercase());
        let content = format!("{env_var}={key}\n");
        encrypt_and_write(&content, &recipient, &dest)?;
    }
    Ok(())
}

/// Cryptographically random bytes, base64-encoded -- Authelia's own docs
/// recommend a value "more than twenty characters"; 32 random bytes
/// (43 base64 characters) comfortably clears that with real entropy,
/// matching the same /dev/urandom source random_hex_key already uses.
fn random_secret_value() -> anyhow::Result<String> {
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| anyhow::anyhow!("failed to open /dev/urandom: {e}"))?;
    std::io::Read::read_exact(&mut f, &mut buf)
        .map_err(|e| anyhow::anyhow!("failed to read from /dev/urandom: {e}"))?;
    Ok(base64_encode(&buf))
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
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

/// Ensures Authelia's two required secrets (jwtSecretFile,
/// storageEncryptionKeyFile) exist, generating and encrypting random
/// values for whichever don't yet. Same idempotency contract as
/// ensure_all: an app whose .sops file already exists is never
/// regenerated or read back.
pub fn ensure_authelia_secrets(secrets_dir: &Path, pubkey_path: &Path) -> anyhow::Result<()> {
    const NAMES: &[&str] = &["authelia-jwt-secret", "authelia-storage-key"];
    let missing: Vec<&&str> = NAMES
        .iter()
        .filter(|name| !secrets_dir.join(format!("{name}.sops")).exists())
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let recipient = host_age_recipient(pubkey_path)?;
    for name in missing {
        let dest = secrets_dir.join(format!("{name}.sops"));
        let value = random_secret_value()?;
        encrypt_and_write(&value, &recipient, &dest)?;
    }
    Ok(())
}

/// Ensures Authelia has a first user: generates a random password, writes
/// its argon2id hash into users_database.yml (Authelia's file-auth-backend
/// format), and writes the one-time PLAINTEXT to a root-only file the
/// operator reads over SSH -- "no default password, ever," satisfied by
/// there being no fixed value anywhere in this codebase for anyone to
/// find. Idempotent: does nothing if users_database.yml already exists,
/// so a second apply never resets an operator's already-changed password.
pub fn ensure_first_authelia_user(
    state_dir: &Path,
    admin_email: &str,
) -> anyhow::Result<()> {
    let users_db = state_dir.join("users_database.yml");
    if users_db.exists() {
        return Ok(());
    }
    let password = random_secret_value()?;
    let hash = argon2id_hash(&password)?;
    let content = format!(
        "users:\n  admin:\n    disabled: false\n    displayname: \"Admin\"\n    password: \"{hash}\"\n    email: \"{admin_email}\"\n    groups:\n      - admins\n"
    );
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(&users_db, content)?;

    let setup_file = state_dir.join("authelia-setup-password");
    std::fs::write(&setup_file, format!("{password}\n"))?;
    let mut perms = std::fs::metadata(&setup_file)?.permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o400);
    std::fs::set_permissions(&setup_file, perms)?;
    Ok(())
}

/// Shells out to Authelia's own `authelia crypto hash generate argon2`
/// (the package already provides this) rather than reimplementing
/// argon2id in Rust -- this is the exact hash format Authelia's own
/// file-backend authentication reads. The "Digest: " line-prefix parsing
/// below is confirmed against real output, not assumed: `nix run
/// nixpkgs#authelia -- crypto hash generate argon2 --password
/// 'test-password-value'` on ferrum-dev printed exactly
/// `Digest: $argon2id$v=19$m=65536,t=3,p=4$npCLidaP2T9KZ6T/YI3iYg$crCL3zlrHJ0fYAd64wJ0SXZ1ClpsekAfcPmrY4oE9lY`
/// while writing this plan.
fn argon2id_hash(password: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("authelia")
        .args(["crypto", "hash", "generate", "argon2", "--password", password])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run authelia crypto hash generate: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "authelia crypto hash generate failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout)?;
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("Digest: "))
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("could not parse hash from authelia output: {stdout}"))
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
        // qbittorrent is not in SERVARR_APPS, so it's filtered out of
        // `missing` before ensure_all ever derives a recipient or shells
        // out to ssh-to-age/sops -- passing a pubkey path that doesn't
        // exist proves that: if ensure_all tried to read it, this would
        // return an error instead of Ok(()), and no real ssh-to-age/sops
        // binary is guaranteed in a plain `cargo test` sandbox anyway.
        let nonexistent_pubkey = dir.path().join("no-such-key.pub");
        let result = ensure_all(dir.path(), &nonexistent_pubkey, &["qbittorrent"]);
        assert!(result.is_ok(), "qbittorrent-only call should short-circuit before touching the host key: {result:?}");
        assert!(!dir.path().join("qbittorrent-apikey.sops").exists());
    }
}
