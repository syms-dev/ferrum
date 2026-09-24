use std::path::Path;

use ferrum_secrets::{encrypt_and_write, host_age_recipient, random_hex_key, random_secret_value};

/// Servarr apps that get an auto-generated API key. qBittorrent has its own
/// WebUI username/password, Plex uses Plex.tv account auth, Jellyfin and
/// SABnzbd have their own first-run setup flows -- none of those four go
/// through this mechanism (see the design spec's Secrets section).
const SERVARR_APPS: &[&str] = &["sonarr", "radarr", "prowlarr"];

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
    let missing = apps_needing_an_apikey(secrets_dir, apps);
    if missing.is_empty() {
        return Ok(());
    }

    let recipient = host_age_recipient(pubkey_path)?;
    for app in missing {
        let key = random_hex_key()?;

        let env_var = format!("{}__AUTH__APIKEY", app.to_uppercase());
        let env_dest = secrets_dir.join(format!("{app}-apikey.sops"));
        encrypt_and_write(&format!("{env_var}={key}\n"), &recipient, &env_dest)?;

        // A second, bare-value representation of the SAME key, generated
        // together so the two can never drift apart -- Recyclarr's own
        // `_secret` mechanism and the reconciler's own API calls (Phase
        // 1.4c) both need the bare value, never the "KEY=VALUE\n" form
        // environmentFiles needs. Confirmed for real against
        // genJqSecretsReplacement's actual source and the real Sonarr/
        // Prowlarr APIs on ferrum-dev while writing that plan -- neither
        // consumer can use `<app>-apikey.sops` directly.
        let raw_dest = secrets_dir.join(format!("{app}-apikey-raw.sops"));
        encrypt_and_write(&format!("{key}\n"), &recipient, &raw_dest)?;
    }
    Ok(())
}

/// Which servarr apps still need a key generated.
///
/// **The guard checks BOTH artifacts, not just the first one written.**
/// `ensure_all` writes `<app>-apikey.sops` and then
/// `<app>-apikey-raw.sops`; keying the guard on the first meant a run
/// killed between the two `encrypt_and_write` calls short-circuited on
/// every later apply and never produced the second. That is not a cosmetic
/// gap: the raw copy is the only form Recyclarr's `_secret` mechanism and
/// the reconciler's API calls can use, and it is named as a `sopsFile`, so
/// `nix build` asserts on it at eval time -- the host could not build a
/// generation again, and the guard guaranteed it never would.
///
/// An app missing either file is regenerated from scratch rather than
/// repaired, because the existing key cannot be read back: it is encrypted
/// to the host and this process has no way to decrypt it. Rotating is safe
/// precisely because the incomplete state is unbuildable -- the generation
/// carrying the old key never activated, so nothing is running with it.
/// Both files are rewritten together, so the two can still never drift.
///
/// Split out of `ensure_all` so the decision can be asserted on without an
/// age recipient or an `ssh-to-age` binary.
///
/// # Arguments
/// * `secrets_dir` - where the `.sops` files live.
/// * `apps` - the enabled apps; non-servarr apps are never candidates.
///
/// # Returns
/// The servarr apps missing either artifact, in the order given.
fn apps_needing_an_apikey<'a>(secrets_dir: &Path, apps: &[&'a str]) -> Vec<&'a str> {
    apps.iter()
        .copied()
        .filter(|app| SERVARR_APPS.contains(app))
        .filter(|app| {
            !secrets_dir.join(format!("{app}-apikey.sops")).exists()
                || !secrets_dir.join(format!("{app}-apikey-raw.sops")).exists()
        })
        .collect()
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
    write_first_user(state_dir, &hash, &password, admin_email)
}

/// The two writes, split out of `ensure_first_authelia_user` so their order
/// can be asserted without an `authelia` binary on PATH -- `argon2id_hash`
/// shells out to one, which is the same reason `render_users_database` was
/// split out.
///
/// **The operator-facing file is written FIRST, and that order is the whole
/// point of this function.** `users_database.yml` is the idempotence guard,
/// and it has to stay the guard: it is the authoritative "a user exists"
/// marker, and an operator who has read and deleted the setup password must
/// not have their password reset by the next apply. But it used to be
/// written first, so a run killed between the two writes left the guard in
/// place while the generated password existed only in the RAM of a process
/// about to exit. Every later apply short-circuited, the plaintext was
/// gone, and the operator could never log into Authelia at all -- the
/// installer's report just said "(could not read ...)". Of the three guards
/// in this file that had this shape, this was the one whose second artifact
/// could not be regenerated without changing it, so checking both artifacts
/// was not an option here; ordering is.
///
/// Writing the password first means the guard file is never created unless
/// the password that opens it has already landed, so an interrupted run
/// leaves no guard and the next apply retries cleanly.
///
/// # Arguments
/// * `state_dir` - Authelia's state directory.
/// * `hash` - the argon2id PHC string for `password`.
/// * `password` - the generated one-time plaintext.
/// * `admin_email` - the first user's address.
///
/// # Errors
/// When either file cannot be created or written.
fn write_first_user(
    state_dir: &Path,
    hash: &str,
    password: &str,
    admin_email: &str,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(state_dir)?;

    // Opened at mode 0o400 from the moment of creation (via OpenOptions),
    // not write-then-chmod -- the old write()-then-chmod() sequence left a
    // brief window where this one-time plaintext password sat at whatever
    // mode the process umask produced, before being narrowed down.
    let setup_file = state_dir.join("authelia-setup-password");
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(&setup_file)?;
    f.write_all(format!("{password}\n").as_bytes())?;
    // Flushed and closed before the guard file is written, so "the password
    // is on disk" is true and not merely buffered when the guard appears.
    f.flush()?;
    drop(f);

    let users_db = state_dir.join("users_database.yml");
    let content = render_users_database(hash, admin_email);
    std::fs::write(&users_db, content)?;
    Ok(())
}

/// Renders Authelia's `users_database.yml`.
///
/// Split out of `ensure_first_authelia_user` so the document can be tested
/// without an `authelia` binary on PATH -- `argon2id_hash` shells out to
/// one, so the only way to exercise the file this function decides the
/// contents of was to have Authelia installed. That is also why the
/// injection below went unnoticed: the rendering had no test at all.
///
/// THIS FILE DECIDES WHO MAY LOG IN. Authelia's file auth backend reads it
/// to answer that question for every gated app on the host and for ferrum's
/// own control plane, so a value that can add a key to it can add an
/// administrator. It used to be built by `format!`, with `admin_email`
/// interpolated raw inside a quoted scalar; a value carrying a `"` and a
/// newline closed the scalar and wrote a second user:
///
///     a@example.test"\n  attacker:\n    groups:\n      - admins
///
/// A replacement `password:` hash is the same move, which is the version
/// that does not need the attacker to already hold a credential.
///
/// ESCAPING, NOT SERIALIZATION, AND THE DIFFERENCE IS DELIBERATE. There is
/// no YAML serializer anywhere in this workspace's dependency tree -- not in
/// `ferrum-apply`, not transitively, confirmed against `crates/Cargo.lock`
/// -- and adding one is a decision for the owner rather than for this fix.
/// So the block structure below is still assembled by hand, and only the
/// SCALARS go through a real serializer.
///
/// `serde_json` is that serializer, and it is not a pun: YAML 1.2 is a
/// superset of JSON, and JSON's escape set (`\"`, `\\`, `\b`, `\f`, `\n`,
/// `\r`, `\t`, `\uXXXX`) is a subset of YAML 1.2's double-quoted escape
/// set, so a JSON string literal IS a valid YAML double-quoted scalar. That
/// means the escaping is done by a library that is already trusted with
/// this repository's settings documents, rather than by an escape table
/// written here that somebody has to keep correct.
///
/// The security property is narrow and worth stating exactly, because it is
/// what makes the residue tolerable: breaking OUT of a double-quoted scalar
/// requires terminating it, which requires an unescaped `"` or a trailing
/// `\`, and `serde_json` escapes both unconditionally. A value can
/// therefore still make this document unparseable -- an exotic Unicode line
/// separator would -- but it cannot add a key to it. Unparseable is a
/// failed apply, which is fail-closed; a second `admins` member is not.
///
/// Emitting the whole document as JSON would be true serialization and was
/// considered. It is rejected because it changes the on-disk shape of a
/// file an external daemon parses, and this workspace cannot run Authelia
/// to check that it still reads it -- `argon2id_hash`'s own shell-out is
/// the reason. Changing a format on the strength of "a superset should
/// accept it" is the kind of claim this project requires evidence for.
///
/// The `password` field is escaped too, though `argon2id_hash` produces a
/// PHC string that needs none. A value that is safe only because its
/// current producer validates it is precisely the arrangement that produced
/// this finding.
///
/// # Arguments
/// * `hash` - the argon2id PHC string for the generated password.
/// * `admin_email` - the operator's address, from `ferrum.auth.adminEmail`.
///
/// # Returns
/// The complete file contents, ending in a newline.
fn render_users_database(hash: &str, admin_email: &str) -> String {
    format!(
        "users:\n  admin:\n    disabled: false\n    displayname: {}\n    password: {}\n    email: {}\n    groups:\n      - admins\n",
        yaml_scalar("Admin"),
        yaml_scalar(hash),
        yaml_scalar(admin_email),
    )
}

/// One value, rendered as a quoted scalar that cannot be broken out of.
///
/// `serde_json::Value::String` rather than `serde_json::to_string`, so that
/// "this cannot fail" is structural instead of an `expect` a reader has to
/// take on trust: `Value`'s `Display` is infallible.
fn yaml_scalar(value: &str) -> String {
    serde_json::Value::String(value.to_string()).to_string()
}

/// Bootstraps SABnzbd's own api_key, which -- unlike the servarr apps --
/// SABnzbd generates and owns itself in a non-declarative sabnzbd.ini
/// (confirmed via nixpkgs' own services.sabnzbd module: only a `configFile`
/// PATH option exists, no attrset-driven config). Writes a minimal ini
/// SABnzbd accepts as a starting point (confirmed for real on ferrum-dev: a
/// sparse [misc] host/port/api_key/enable_https ini boots cleanly and
/// SABnzbd fills in its own remaining defaults, honoring the preset
/// api_key for real authenticated calls -- verified 403 with a wrong key,
/// 200 with the real one) BEFORE SABnzbd's own first start, so ferrum
/// controls the key from day one instead of trying to scrape it out of
/// SABnzbd's own generated file after the fact. Also the first code that
/// makes ferrum.apps.sabnzbd.port control SABnzbd's real listening port --
/// nixpkgs' own module never passes a --port argument, so only this ini
/// key does anything (found while investigating this exact bootstrap
/// question). Idempotent: does nothing if sabnzbd.ini already exists,
/// matching ensure_first_authelia_user's exact contract -- a second apply
/// never resets an operator's already-customized SABnzbd config. The same
/// key is also sops-encrypted (bare value -- SABnzbd itself never reads
/// this copy via EnvironmentFile=, only Recyclarr/the reconciler do) so
/// both can read it back the same way they read every other app's key.
pub fn ensure_sabnzbd_apikey(
    state_dir: &Path,
    secrets_dir: &Path,
    pubkey_path: &Path,
    port: u16,
) -> anyhow::Result<()> {
    let ini_path = state_dir.join("sabnzbd.ini");
    if !sabnzbd_needs_bootstrap(state_dir, secrets_dir) {
        return Ok(());
    }
    let key = random_hex_key()?;
    let content = format!(
        "[misc]\nhost = 127.0.0.1\nport = {port}\napi_key = {key}\nenable_https = 0\n"
    );
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(&ini_path, content)?;

    let recipient = host_age_recipient(pubkey_path)?;
    let dest = secrets_dir.join("sabnzbd-apikey.sops");
    encrypt_and_write(&format!("{key}\n"), &recipient, &dest)?;
    Ok(())
}

/// Whether SABnzbd still needs its bootstrap ini and encrypted key.
///
/// **Checks BOTH artifacts.** `ensure_sabnzbd_apikey` writes `sabnzbd.ini`
/// and then `sabnzbd-apikey.sops`; keying the guard on the ini alone meant
/// a run killed between the two short-circuited on every later apply and
/// never produced the `.sops` file. It is named as a `sopsFile`, so `nix
/// build` asserts on it at eval time and the host cannot build a generation
/// until it exists.
///
/// Both are rewritten together when either is missing. The key could in
/// principle be recovered from the ini, which holds it in plaintext, but
/// regenerating is simpler and equally safe: the incomplete state is
/// unbuildable, so SABnzbd never started with the old key.
///
/// Split out of `ensure_sabnzbd_apikey` so the decision can be asserted on
/// without an age recipient or an `ssh-to-age` binary.
///
/// # Arguments
/// * `state_dir` - where `sabnzbd.ini` is written.
/// * `secrets_dir` - where `sabnzbd-apikey.sops` is written.
///
/// # Returns
/// `true` when either artifact is missing.
fn sabnzbd_needs_bootstrap(state_dir: &Path, secrets_dir: &Path) -> bool {
    !state_dir.join("sabnzbd.ini").exists()
        || !secrets_dir.join("sabnzbd-apikey.sops").exists()
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

    /// A real argon2id PHC string, shaped exactly as `argon2id_hash`
    /// returns one. A literal rather than a call, because that function
    /// shells out to the `authelia` binary.
    const A_REAL_HASH: &str =
        "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHR2YWx1ZQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

    /// The user keys the rendered document actually declares.
    ///
    /// A user key sits at exactly two spaces of indent and ends in a colon;
    /// `groups:` and the other fields sit at four and are excluded. This is
    /// deliberately structural rather than a substring search for
    /// "attacker": an escaped payload still CONTAINS that text, on the one
    /// line of the quoted scalar holding it, and a test that looked for the
    /// text alone would fail on a correctly-escaped document.
    fn user_keys(document: &str) -> Vec<&str> {
        document
            .lines()
            .filter(|line| {
                line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':')
            })
            .map(|line| line.trim().trim_end_matches(':'))
            .collect()
    }

    // -----------------------------------------------------------------
    // Idempotence guards: each function writes two artifacts, and a kill
    // between the two writes must not make every later apply short-circuit
    // past the one that never got written.
    // -----------------------------------------------------------------

    /// `<app>-apikey-raw.sops` missing means the run died between the two
    /// `encrypt_and_write` calls, and the app must be regenerated.
    ///
    /// The bare-value copy is what Recyclarr's `_secret` mechanism and the
    /// reconciler's own API calls read; the `KEY=VALUE` copy is unusable to
    /// either. Worse, the missing file is named as a `sopsFile`, so `nix
    /// build` asserts on it at eval time -- the host cannot build a
    /// generation again until it exists, and the guard guaranteed it never
    /// would.
    #[test]
    fn an_app_missing_only_its_raw_key_still_needs_generating() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sonarr-apikey.sops"), "x").unwrap();
        assert_eq!(
            apps_needing_an_apikey(dir.path(), &["sonarr"]),
            vec!["sonarr"],
            "the second artifact was never written, so this is not done"
        );
    }

    /// The mirror case, for completeness: the env-file copy missing while
    /// the raw copy exists is the same interrupted run seen from the other
    /// side.
    #[test]
    fn an_app_missing_only_its_env_key_still_needs_generating() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sonarr-apikey-raw.sops"), "x").unwrap();
        assert_eq!(apps_needing_an_apikey(dir.path(), &["sonarr"]), vec!["sonarr"]);
    }

    /// And the guard must still short-circuit when the work really is done,
    /// or "regenerate when incomplete" becomes "rotate every key on every
    /// apply".
    #[test]
    fn an_app_with_both_artifacts_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sonarr-apikey.sops"), "x").unwrap();
        std::fs::write(dir.path().join("sonarr-apikey-raw.sops"), "x").unwrap();
        assert!(apps_needing_an_apikey(dir.path(), &["sonarr"]).is_empty());
        // ...and a non-servarr app is never a candidate at all.
        assert!(apps_needing_an_apikey(dir.path(), &["plex", "jellyfin"]).is_empty());
    }

    /// `sabnzbd.ini` present without `sabnzbd-apikey.sops` is the same
    /// interrupted run, and leaves a `sopsFile` that `nix build` asserts on
    /// missing forever.
    #[test]
    fn sabnzbd_missing_only_its_encrypted_key_still_needs_bootstrapping() {
        let state = tempfile::tempdir().unwrap();
        let secrets = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("sabnzbd.ini"), "[misc]\n").unwrap();
        assert!(sabnzbd_needs_bootstrap(state.path(), secrets.path()));
    }

    #[test]
    fn sabnzbd_with_both_artifacts_is_left_alone() {
        let state = tempfile::tempdir().unwrap();
        let secrets = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("sabnzbd.ini"), "[misc]\n").unwrap();
        std::fs::write(secrets.path().join("sabnzbd-apikey.sops"), "x").unwrap();
        assert!(!sabnzbd_needs_bootstrap(state.path(), secrets.path()));
    }

    /// The Authelia password is the one value here that cannot be
    /// regenerated without CHANGING it, so its guard cannot simply check
    /// both artifacts: `users_database.yml` must stay authoritative, or a
    /// second apply resets an operator's already-changed password.
    ///
    /// The fix is ordering. The operator-facing file is written FIRST, so
    /// the guard file is never created unless the password that opens it
    /// has already landed. This test makes the password write fail -- by
    /// occupying its path with a directory -- and asserts the guard file
    /// was not created, which is the property that lets the next apply
    /// retry cleanly.
    ///
    /// Under the old order the guard file was written first, so this exact
    /// failure left `users_database.yml` on disk with the password existing
    /// only in the RAM of a process that was about to exit: every later
    /// apply short-circuited, and the operator could never log into
    /// Authelia. The installer's own report said "(could not read ...)".
    #[test]
    fn a_failed_password_write_does_not_leave_the_guard_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        // Occupy the password path with a directory, so opening it for
        // writing fails with EISDIR.
        std::fs::create_dir(dir.path().join("authelia-setup-password")).unwrap();

        let err = write_first_user(dir.path(), A_REAL_HASH, "s3cret", "admin@example.test");
        assert!(err.is_err(), "the password write must fail in this setup");
        assert!(
            !dir.path().join("users_database.yml").exists(),
            "the guard file must not survive a run that never delivered the \
             password -- it is what stops the next apply from retrying"
        );
    }

    /// ...and the successful path still writes both, so the ordering fix
    /// cannot be satisfied by never writing the guard file.
    #[test]
    fn a_successful_first_user_writes_both_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        write_first_user(dir.path(), A_REAL_HASH, "s3cret", "admin@example.test").unwrap();
        assert!(dir.path().join("users_database.yml").exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("authelia-setup-password")).unwrap(),
            "s3cret\n"
        );
    }

    /// The headline property: `users_database.yml` decides who may log in,
    /// so no value reaching it may add a key to it.
    ///
    /// The payload is the one from the security review, which produced a
    /// second `admins` member against the `format!` this replaced.
    #[test]
    fn an_admin_email_cannot_add_a_second_user_to_the_authelia_database() {
        let payload = "a@example.test\"\n  attacker:\n    groups:\n      - admins";
        let document = render_users_database(A_REAL_HASH, payload);
        assert_eq!(
            user_keys(&document),
            vec!["admin"],
            "the email field added a user to the file that decides who may log in:\n{document}"
        );
        assert_eq!(
            document.lines().filter(|l| l.trim() == "- admins").count(),
            1,
            "exactly one account may be an admin:\n{document}"
        );
    }

    /// The same move through `password:`, which is the version that does
    /// not need the attacker to hold a credential first -- it replaces the
    /// hash rather than adding a user beside it.
    ///
    /// `argon2id_hash` cannot currently produce such a value. The field is
    /// escaped anyway: "safe because its producer validates it" is the
    /// arrangement that produced this finding.
    #[test]
    fn a_password_hash_cannot_rewrite_the_document_around_it() {
        let payload = "$argon2id$fake\"\n  attacker:\n    password: \"$argon2id$mine";
        let document = render_users_database(payload, "admin@example.test");
        assert_eq!(user_keys(&document), vec!["admin"], "{document}");
    }

    /// Escaping that handles the quote but not the backslash is the classic
    /// half-fix: a value ending in `\` makes the NEXT character an escape,
    /// so the closing quote stops closing anything and the scalar runs on
    /// into the structure below it.
    #[test]
    fn a_trailing_backslash_cannot_swallow_the_closing_quote() {
        let payload = "a@example.test\\";
        let document = render_users_database(A_REAL_HASH, payload);
        assert!(
            document.contains(r#""a@example.test\\""#),
            "a backslash must be escaped as well as the quote:\n{document}"
        );
        assert_eq!(user_keys(&document), vec!["admin"], "{document}");
    }

    /// A bare newline with no quote, which cannot close the scalar but must
    /// still not reach the file as a real line break -- inside a quoted
    /// scalar YAML would fold it, so the document would parse differently
    /// from the value that was supplied.
    #[test]
    fn a_control_character_never_reaches_the_file_raw() {
        let document = render_users_database(A_REAL_HASH, "a@example.test\nb\tc");
        let email_line = document
            .lines()
            .find(|line| line.trim_start().starts_with("email:"))
            .expect("the document must still have an email field");
        assert!(email_line.contains("\\n") && email_line.contains("\\t"), "{email_line}");
        assert_eq!(
            document.lines().count(),
            8,
            "the document must keep its eight lines whatever the value contained:\n{document}"
        );
    }

    /// The other direction. An escaper that mangled ordinary input would
    /// pass every test above while breaking every real host, so the exact
    /// bytes for a normal address are pinned -- including that this is
    /// still the same document Authelia was already being given.
    #[test]
    fn an_ordinary_address_renders_the_document_authelia_already_reads() {
        let document = render_users_database(A_REAL_HASH, "admin@example.test");
        assert_eq!(
            document,
            format!(
                "users:\n  admin:\n    disabled: false\n    displayname: \"Admin\"\n    \
                 password: \"{A_REAL_HASH}\"\n    email: \"admin@example.test\"\n    \
                 groups:\n      - admins\n"
            ),
            "the rendering changed for an ordinary address"
        );
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

    #[test]
    fn ensure_authelia_secrets_is_idempotent_when_both_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("authelia-jwt-secret.sops"), b"fake").unwrap();
        std::fs::write(dir.path().join("authelia-storage-key.sops"), b"fake").unwrap();
        // Both files already exist, so `missing` is empty and ensure_authelia_secrets
        // must return Ok(()) without ever deriving a recipient or touching the host
        // key -- a nonexistent pubkey path proves that: if it tried to read it,
        // this would return an error instead of Ok(()).
        let nonexistent_pubkey = dir.path().join("no-such-key.pub");
        let result = ensure_authelia_secrets(dir.path(), &nonexistent_pubkey);
        assert!(result.is_ok(), "should short-circuit when both secrets already exist: {result:?}");
    }

    #[test]
    fn ensure_all_generates_a_matched_raw_secret_alongside_the_env_var_one() {
        let dir = tempfile::tempdir().unwrap();
        let pubkey = dir.path().join("host.pub");
        std::fs::write(&pubkey, "not-a-real-ssh-key").unwrap();
        // ensure_all shells out to ssh-to-age/sops; without a real
        // recipient this will fail before writing anything -- this test
        // only exercises the case where both files already exist (the
        // short-circuit, same technique ensure_all_only_touches_servarr_apps
        // already uses), which is what actually proves the two-file
        // behavior didn't break the existing idempotency contract.
        let dest = dir.path().join("sonarr-apikey.sops");
        std::fs::write(&dest, "SONARR__AUTH__APIKEY=deadbeef\n").unwrap();
        let raw_dest = dir.path().join("sonarr-apikey-raw.sops");
        std::fs::write(&raw_dest, "deadbeef\n").unwrap();
        let result = ensure_all(dir.path(), &pubkey, &["sonarr"]);
        assert!(result.is_ok(), "should short-circuit when both files already exist: {result:?}");
    }

    /// This test set up only `sabnzbd.ini` -- the half-complete state left
    /// by a run killed between the two writes -- and asserted the function
    /// short-circuits on it. That assertion was the defect, not the
    /// contract: short-circuiting there is exactly what left
    /// `sabnzbd-apikey.sops` missing forever. It now sets up BOTH
    /// artifacts, which is the same technique its sibling
    /// `ensure_all_is_idempotent_when_both_files_exist` was already using
    /// one screen above.
    #[test]
    fn ensure_sabnzbd_apikey_is_idempotent_when_both_artifacts_exist() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("sabnzbd.ini"), "[misc]\napi_key = existing\n").unwrap();
        std::fs::write(dir.path().join("sabnzbd-apikey.sops"), "existing\n").unwrap();
        let nonexistent_pubkey = dir.path().join("no-such-key.pub");
        let result = ensure_sabnzbd_apikey(&state_dir, dir.path(), &nonexistent_pubkey, 8080);
        assert!(result.is_ok(), "should short-circuit before touching the host key: {result:?}");
        let content = std::fs::read_to_string(state_dir.join("sabnzbd.ini")).unwrap();
        assert_eq!(content, "[misc]\napi_key = existing\n", "must not overwrite an existing ini");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("sabnzbd-apikey.sops")).unwrap(),
            "existing\n",
            "nor the encrypted key beside it"
        );
    }

    #[test]
    fn ensure_sabnzbd_apikey_bootstrap_ini_contains_the_configured_port() {
        // Confirms the port actually lands in the generated ini without
        // needing a real age recipient -- writes the ini, then fails on
        // the sops step, which is fine: this test only checks the ini's
        // own content, written before that step runs.
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let nonexistent_pubkey = dir.path().join("no-such-key.pub");
        let _ = ensure_sabnzbd_apikey(&state_dir, dir.path(), &nonexistent_pubkey, 9090);
        let content = std::fs::read_to_string(state_dir.join("sabnzbd.ini")).unwrap();
        assert!(content.contains("port = 9090"), "ini did not contain the configured port: {content}");
        assert!(content.contains("api_key = "), "ini did not contain a generated api_key: {content}");
    }
}
