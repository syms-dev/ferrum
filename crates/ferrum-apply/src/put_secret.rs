//! `ferrum-apply put-secret <name>` -- the first path by which an *operator*
//! supplies a secret value to a ferrum host.
//!
//! Every other function in `secrets.rs` generates a value it invents
//! (`ensure_all`, `ensure_authelia_secrets`, `ensure_first_authelia_user`,
//! `ensure_sabnzbd_apikey`). Nothing accepted a value from outside, which
//! `modules/core/secrets.nix` records as "a later ferrumd change". The
//! Phase 1.6a installer needs one: a host with any `public` app cannot
//! build at all until `<secretsDir>/acme-dns.sops` exists, because
//! `modules/proxy/acme.nix` asserts both that `ferrum.secrets` declares the
//! name AND that the file is present at Nix *evaluation* time -- and the
//! Cloudflare token it holds can only be encrypted to the host's own age
//! recipient, which is derived from a host key that does not exist until
//! the host does.
//!
//! The value is read from stdin rather than taken as an argument so it
//! never appears in `ps`, a shell history, or this process's own argv.

use std::io::Read;
use std::path::Path;

use ferrum_secrets::{encrypt_and_write, host_age_recipient};

/// What `put_secret_in` did, so the caller can report it truthfully rather
/// than saying "wrote" when it deliberately left an existing file alone.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Wrote,
    Replaced,
    /// The file already existed and `replace` was not set. This is the
    /// idempotent path a resumed install takes (see the spec's R7): a
    /// second stage-2 attempt must not fail merely because the first one
    /// got this far.
    Unchanged,
}

/// Rejects any name that is not a plain lowercase secret identifier.
///
/// This is an allowlist on purpose. The name becomes a path component under
/// `secretsDir`, so a denylist for `..` and `/` would be one encoding trick
/// away from writing outside it; every real secret in the tree
/// (`acme-dns`, `authelia-jwt-secret`, `sabnzbd-apikey`, `qbittorrent-vpn`)
/// already matches this shape.
pub fn validate_secret_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("secret name is empty");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        anyhow::bail!(
            "secret name {name:?} is not a plain secret identifier \
             (lowercase letters, digits and '-' only)"
        );
    }
    if name.starts_with('-') || name.ends_with('-') {
        anyhow::bail!("secret name {name:?} must not start or end with '-'");
    }
    Ok(())
}

/// Encrypts `value` to this host's age recipient and writes it to
/// `<secrets_dir>/<name>.sops`.
///
/// `encrypt` is injected so tests exercise every branch without `sops` on
/// PATH or a real SSH host key -- the same reason the rest of this crate
/// splits `_in` variants out of its env-reading entry points.
///
/// # Errors
/// Returns an error if the name is not a plain identifier, the value is
/// empty, or the encrypt step fails. An existing file is never read back:
/// this process cannot decrypt it.
pub fn put_secret_in(
    secrets_dir: &Path,
    name: &str,
    value: &str,
    replace: bool,
    encrypt: impl FnOnce(&str, &Path) -> anyhow::Result<()>,
) -> anyhow::Result<Outcome> {
    validate_secret_name(name)?;
    if value.is_empty() {
        anyhow::bail!("refusing to write an empty value for secret {name:?}");
    }

    let dest = secrets_dir.join(format!("{name}.sops"));
    let existed = dest.exists();
    if existed && !replace {
        return Ok(Outcome::Unchanged);
    }

    encrypt(value, &dest)?;
    Ok(if existed {
        Outcome::Replaced
    } else {
        Outcome::Wrote
    })
}

/// Reads the whole of stdin as the secret value and writes it.
///
/// The value is written byte-for-byte as supplied. That is deliberate and
/// load-bearing: `acme-dns` must contain the systemd `EnvironmentFile=`
/// line `CLOUDFLARE_DNS_API_TOKEN=<token>` rather than a bare token,
/// because `modules/proxy/acme.nix` hands the decrypted file to systemd as
/// an environment file. Trimming or reformatting here would silently
/// produce a file ACME cannot use.
pub fn run(
    secrets_dir: &Path,
    pubkey_path: &Path,
    name: &str,
    replace: bool,
) -> anyhow::Result<Outcome> {
    let mut value = String::new();
    std::io::stdin().read_to_string(&mut value)?;

    // Validate before touching the host key: a bad name should not require
    // a readable SSH host key to be reported.
    validate_secret_name(name)?;
    if value.is_empty() {
        anyhow::bail!("refusing to write an empty value for secret {name:?}");
    }

    let dest = secrets_dir.join(format!("{name}.sops"));
    if dest.exists() && !replace {
        return Ok(Outcome::Unchanged);
    }

    let recipient = host_age_recipient(pubkey_path)?;
    put_secret_in(secrets_dir, name, &value, replace, |v, d| {
        encrypt_and_write(v, &recipient, d)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_encrypt(value: &str, dest: &Path) -> anyhow::Result<()> {
        std::fs::write(dest, format!("ENCRYPTED:{value}"))?;
        Ok(())
    }

    #[test]
    fn writes_a_new_secret() {
        let dir = tempfile::tempdir().unwrap();
        let out = put_secret_in(dir.path(), "acme-dns", "TOKEN=abc\n", false, ok_encrypt).unwrap();
        assert_eq!(out, Outcome::Wrote);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("acme-dns.sops")).unwrap(),
            "ENCRYPTED:TOKEN=abc\n"
        );
    }

    /// The resume path: a second stage-2 attempt must not fail, and must
    /// not silently rewrite a secret the operator may have rotated.
    #[test]
    fn leaves_an_existing_secret_alone_without_replace() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("acme-dns.sops"), "ORIGINAL").unwrap();

        let out = put_secret_in(dir.path(), "acme-dns", "TOKEN=new\n", false, |_, _| {
            panic!("must not encrypt when the file already exists and replace is false")
        })
        .unwrap();

        assert_eq!(out, Outcome::Unchanged);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("acme-dns.sops")).unwrap(),
            "ORIGINAL"
        );
    }

    #[test]
    fn replace_overwrites_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("acme-dns.sops"), "ORIGINAL").unwrap();
        let out = put_secret_in(dir.path(), "acme-dns", "TOKEN=new\n", true, ok_encrypt).unwrap();
        assert_eq!(out, Outcome::Replaced);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("acme-dns.sops")).unwrap(),
            "ENCRYPTED:TOKEN=new\n"
        );
    }

    /// The value is a systemd EnvironmentFile line, not a bare token, and
    /// must survive byte-for-byte.
    #[test]
    fn writes_the_value_verbatim_without_trimming() {
        let dir = tempfile::tempdir().unwrap();
        let payload = "CLOUDFLARE_DNS_API_TOKEN=  spaced-value  \n";
        put_secret_in(dir.path(), "acme-dns", payload, false, ok_encrypt).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("acme-dns.sops")).unwrap(),
            format!("ENCRYPTED:{payload}")
        );
    }

    #[test]
    fn refuses_an_empty_value() {
        let dir = tempfile::tempdir().unwrap();
        let err = put_secret_in(dir.path(), "acme-dns", "", false, ok_encrypt).unwrap_err();
        assert!(err.to_string().contains("empty value"), "{err}");
        assert!(!dir.path().join("acme-dns.sops").exists());
    }

    /// The security property: a name is a path component, so anything that
    /// could escape `secrets_dir` must be refused before any write.
    #[test]
    fn refuses_names_that_could_escape_the_secrets_dir() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "../evil",
            "..",
            "a/b",
            "/etc/passwd",
            "acme dns",
            "ACME-DNS",
            "acme_dns",
            "acme.dns",
            "",
            "-leading",
            "trailing-",
            "a\0b",
        ] {
            let err = put_secret_in(dir.path(), bad, "v", false, |_, _| {
                panic!("must not encrypt for rejected name {bad:?}")
            })
            .unwrap_err();
            assert!(
                err.to_string().contains("secret name"),
                "name {bad:?} gave the wrong error: {err}"
            );
        }
    }

    #[test]
    fn accepts_every_secret_name_the_tree_actually_uses() {
        for good in [
            "acme-dns",
            "authelia-jwt-secret",
            "authelia-storage-key",
            "sabnzbd-apikey",
            "qbittorrent-vpn",
            "sonarr-apikey-raw",
            "restic-password",
        ] {
            validate_secret_name(good).unwrap_or_else(|e| panic!("rejected {good:?}: {e}"));
        }
    }

    /// An encrypt failure must not leave a partial or misleading file
    /// behind, and must surface rather than be swallowed.
    #[test]
    fn propagates_an_encrypt_failure() {
        let dir = tempfile::tempdir().unwrap();
        let err = put_secret_in(dir.path(), "acme-dns", "v", false, |_, _| {
            anyhow::bail!("sops exploded")
        })
        .unwrap_err();
        assert!(err.to_string().contains("sops exploded"), "{err}");
        assert!(!dir.path().join("acme-dns.sops").exists());
    }
}
