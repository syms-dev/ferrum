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

/// Where `ensure_root_password` writes the generated console password when
/// nothing overrides it.
///
/// Named here and wired into the real binary by
/// `modules/core/overlays.nix`'s `FERRUM_ROOT_PASSWORD_FILE`, the same way
/// every other `FERRUM_*` default reaches this process. The installer's
/// closing report reads it back over SSH -- see `credential_paths` in
/// `crates/ferrum-install/src/verify.rs`, which names the same literal for
/// the same reason it already names `authelia-setup-password`'s: the
/// installer runs on the operator's own machine and links no code from
/// this crate.
pub const DEFAULT_ROOT_PASSWORD_FILE: &str = "/var/lib/ferrum/root-console-password";

/// Ensures root can log in at the physical console, generating a random
/// password and writing the one-time plaintext to `setup_file` if it
/// currently cannot.
///
/// **THIS EXISTS BECAUSE A FERRUM HOST COULD STRAND ITS OWN OWNER.** Nothing
/// in this module tree ever set `hashedPassword`, `initialPassword` or
/// `users.mutableUsers`, so root's password was never set at all and the
/// account was locked. That is invisible while SSH answers and total the
/// moment it does not: a real host stopped listening on 22, 80 and 443
/// while still reaching `ferrum login:`, and that prompt accepted nothing
/// because there was nothing to accept. The only way back in was editing
/// the bootloader for `init=/bin/sh`, which then broke the keyboard --
/// that path never starts systemd, so udev never loads the USB HID driver.
/// An appliance whose recovery story is "take the boot process apart" is
/// not finished.
///
/// The guard is the REAL STATE, never a marker file: `passwd -S root` is
/// asked whether root actually has a usable password. That distinction is
/// the whole design. Three idempotence guards in this file were once keyed
/// on the first of two artifacts they wrote, so a run killed between the
/// two writes made every later apply short-circuit past the second
/// forever; `ensure_first_authelia_user` was the worst, leaving a generated
/// password that existed only in the RAM of a process about to exit. A
/// guard keyed on `setup_file.exists()` would reproduce exactly that, and
/// would lie in the other direction too: an operator who read their
/// password and deleted the file would be handed a new one on the next
/// apply, silently replacing the one they had memorised.
///
/// Asking the real state also gives the second required property for free.
/// An operator who has set their own root password by hand -- at the
/// console, during exactly the incident above -- reports `P`, so this
/// function does nothing and never overwrites it.
///
/// `users.mutableUsers` is left at NixOS's own default of `true`, which is
/// what makes a password set at runtime survive every later rebuild.
/// Confirmed on the generated configuration rather than assumed, and kept
/// that way by `a-host-always-has-a-way-in` in
/// `nix/modules/flake/checks.nix`: if some module ever set it to `false`,
/// activation would wipe this password on the next switch and this whole
/// approach would stop working, so that check is what says so.
///
/// # Arguments
/// * `setup_file` - where the one-time plaintext is written, mode `0400`.
///
/// # Errors
/// When `passwd -S root` cannot be run or reports something this code does
/// not recognise, when the setup file cannot be written, or when
/// `chpasswd` refuses the new password.
pub fn ensure_root_password(setup_file: &Path) -> anyhow::Result<()> {
    ensure_root_password_for(setup_file, &root_password_status()?, set_root_password)
}

/// The decision and both effects, with the privileged read and the
/// privileged write passed in.
///
/// Split this way so the whole function -- not merely its parts -- can be
/// put in front of every state `passwd -S root` can report, from a test
/// running unprivileged in a sandbox that has neither `passwd` nor
/// `chpasswd`. Both properties that matter are properties of the
/// SEQUENCE, so testing the pieces separately would have covered neither.
///
/// **The plaintext file is written FIRST, and that order is deliberate.**
/// The password becomes root's only once `set` returns, so a run killed
/// between the two leaves root still without one -- which the guard reports
/// as `L`/`NP`, so the next apply generates again and overwrites the stale
/// file. Setting the password first would invert that: the guard would
/// report `P` forever while the plaintext died with the process, and the
/// operator would be locked out by the very code meant to let them in.
/// That is precisely how `ensure_first_authelia_user` used to fail.
///
/// # Arguments
/// * `setup_file` - where the one-time plaintext is written.
/// * `passwd_status` - the raw stdout of `passwd -S root`.
/// * `set` - applies the password to the real account.
///
/// # Errors
/// When `passwd_status` is unrecognised, the file cannot be written, or
/// `set` fails.
fn ensure_root_password_for(
    setup_file: &Path,
    passwd_status: &str,
    set: impl FnOnce(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if !root_needs_a_password(passwd_status)? {
        return Ok(());
    }
    let password = random_secret_value()?;
    write_root_password(setup_file, &password)?;
    set(&password)
}

/// Whether root currently has no usable password, read from `passwd -S`'s
/// own output.
///
/// shadow's second field is the account's password status: `P` for a
/// usable password, `NP` for none at all, `L` for locked. A ferrum host
/// built before this function existed reports `L`.
///
/// **An unrecognised status is an error, not a guess.** The two available
/// guesses are harmful in opposite directions -- assuming "set" strands an
/// operator who has no password, assuming "not set" overwrites one they
/// chose -- so neither is taken. A loud failure of `ferrum-apply apply` is
/// recoverable; silently destroying the operator's own credential is not.
/// The account name is checked for the same reason: `passwd -S` with no
/// argument reports on the CALLING user, and a status line describing
/// somebody else must never be read as an answer about root.
///
/// # Arguments
/// * `passwd_status` - the raw stdout of `passwd -S root`.
///
/// # Returns
/// `true` when root has no usable password and one should be generated.
///
/// # Errors
/// When the output is empty, describes an account other than root, or
/// carries a status token this code does not recognise.
fn root_needs_a_password(passwd_status: &str) -> anyhow::Result<bool> {
    let line = passwd_status
        .lines()
        .find(|line| !line.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("`passwd -S root` printed nothing at all"))?;
    let mut fields = line.split_whitespace();
    match fields.next() {
        Some("root") => {}
        Some(other) => {
            anyhow::bail!("`passwd -S root` reported on the account {other:?}, not root: {line:?}")
        }
        None => anyhow::bail!("`passwd -S root` printed no account name: {line:?}"),
    }
    match fields.next() {
        Some("P") => Ok(false),
        Some("L" | "NP") => Ok(true),
        Some(other) => anyhow::bail!(
            "`passwd -S root` reported the unrecognised password status {other:?} \
             (expected P, L or NP): {line:?} -- refusing to guess, because either \
             guess strands you at the console or overwrites a password you chose"
        ),
        None => anyhow::bail!("`passwd -S root` printed no password status: {line:?}"),
    }
}

/// Asks shadow for root's real account state.
///
/// `passwd` reaches this process through the wrapper in
/// `nix/pkgs/ferrum-apply/default.nix`, which puts `shadow` on PATH the
/// same way it already supplies `btrfs`, `sops`, `ssh-to-age`, `authelia`
/// and `dig` -- so this does not depend on a consuming systemd unit
/// remembering to provide it.
///
/// # Returns
/// The raw stdout of `passwd -S root`.
///
/// # Errors
/// When the binary cannot be run or exits non-zero.
fn root_password_status() -> anyhow::Result<String> {
    let output = std::process::Command::new("passwd")
        .args(["-S", "root"])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `passwd -S root`: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`passwd -S root` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Writes the one-time plaintext where the operator -- and the installer's
/// closing report -- can read it.
///
/// Opened at mode `0400` from the moment of creation via `OpenOptions`,
/// never write-then-chmod: that sequence leaves a window where a plaintext
/// root password sits at whatever mode the process umask produced. The
/// same fix was made to `write_first_user`, for the same reason.
///
/// **Any existing file is REMOVED first, and that is not tidiness.**
/// `OpenOptions::mode` applies only when the file is created; reopening an
/// existing one leaves whatever mode it already had, so a rewrite over a
/// file somebody had loosened would silently keep it loose -- a plaintext
/// root password at the wrong mode is the exact thing the line above
/// exists to prevent. Reopening also cannot work at all here: this
/// function's own previous run left the file at `0400`, which is not
/// writable, and only root's permission bypass hides that. The Nix build
/// sandbox, which is unprivileged, does not have that bypass and reported
/// it as `Permission denied` -- so this is also the difference between a
/// test that passes because it happens to run as root and one that proves
/// something.
///
/// Flushed before returning, so "the password is on disk" is true rather
/// than merely buffered by the time the caller sets it on the real account.
///
/// # Arguments
/// * `setup_file` - the destination path; its parent directory is created.
/// * `password` - the generated one-time plaintext.
///
/// # Errors
/// When the parent directory or the file cannot be created or written. A
/// missing file is not an error to remove.
fn write_root_password(setup_file: &Path, password: &str) -> anyhow::Result<()> {
    if let Some(parent) = setup_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::remove_file(setup_file) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(setup_file)?;
    f.write_all(format!("{password}\n").as_bytes())?;
    f.flush()?;
    Ok(())
}

/// Applies `password` to the real root account via `chpasswd`.
///
/// Fed on stdin rather than passed as an argument, so the plaintext never
/// appears in this host's process table.
///
/// `random_secret_value` produces base64 over `[A-Za-z0-9+/=]`, which
/// contains neither the `:` that separates chpasswd's two fields nor the
/// newline that ends its record -- so the line below cannot be split apart
/// by its own payload.
///
/// # Arguments
/// * `password` - the generated plaintext.
///
/// # Errors
/// When `chpasswd` cannot be run, its stdin cannot be written, or it exits
/// non-zero.
fn set_root_password(password: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut child = std::process::Command::new("chpasswd")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to run chpasswd: {e}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("chpasswd gave us no stdin to write to"))?
        .write_all(format!("root:{password}\n").as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write root's new password to chpasswd: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("failed to wait for chpasswd: {e}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "chpasswd failed to set root's password: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
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

    // -----------------------------------------------------------------
    // The console password: a ferrum host must never boot to a login
    // prompt that accepts nothing. See `ensure_root_password`'s own
    // documentation for the incident these tests exist to keep closed.
    // -----------------------------------------------------------------

    /// Real `passwd -S` output shapes, captured from shadow's documented
    /// format. The trailing fields are the ageing policy; only the first
    /// two are read, and the rest are present so the parser is exercised
    /// against a whole line rather than the two tokens it cares about.
    const ROOT_LOCKED: &str = "root L 2026-09-30 0 99999 7 -1\n";
    const ROOT_NO_PASSWORD: &str = "root NP 2026-09-30 0 99999 7 -1\n";
    const ROOT_HAS_ONE: &str = "root P 2026-09-30 0 99999 7 -1\n";

    /// The defect itself: a host whose root account is locked gets a real,
    /// random password, and the operator can read it.
    #[test]
    fn a_locked_root_account_gets_a_generated_password() {
        let dir = tempfile::tempdir().unwrap();
        let setup_file = dir.path().join("state").join("root-console-password");
        // The stand-in for `chpasswd`: records what it was handed, so the
        // password the account got can be compared with the one the
        // operator is told to type.
        let seen = std::cell::RefCell::new(None::<String>);

        ensure_root_password_for(&setup_file, ROOT_LOCKED, |password| {
            *seen.borrow_mut() = Some(password.to_string());
            Ok(())
        })
        .unwrap();

        let on_disk = std::fs::read_to_string(&setup_file).unwrap();
        let applied = seen.into_inner().expect("chpasswd was never called");
        assert_eq!(
            on_disk,
            format!("{applied}\n"),
            "the password the operator reads must be the password the account got"
        );
        assert!(
            applied.len() >= 20,
            "a console password this short is not real entropy: {applied:?}"
        );
        assert!(
            !applied.contains(':') && !applied.contains('\n'),
            "a password carrying chpasswd's own field or record separator could split \
             its input line: {applied:?}"
        );
    }

    /// `NP` -- no password at all -- is the other unusable state, and it
    /// must be treated exactly like `L`.
    #[test]
    fn a_root_account_with_no_password_at_all_gets_one_too() {
        let dir = tempfile::tempdir().unwrap();
        let setup_file = dir.path().join("root-console-password");
        let seen = std::cell::RefCell::new(None::<String>);

        ensure_root_password_for(&setup_file, ROOT_NO_PASSWORD, |password| {
            *seen.borrow_mut() = Some(password.to_string());
            Ok(())
        })
        .unwrap();

        assert!(
            seen.into_inner().is_some(),
            "NP means no usable password, so one must be generated"
        );
        assert!(setup_file.exists());
    }

    /// **The property the whole design turns on.** The operator set their
    /// own root password by hand -- during exactly the incident this
    /// mechanism exists to prevent -- and then deleted, or never had, the
    /// setup file. A later apply must not touch the account.
    ///
    /// The setup file is deliberately ABSENT here. That is what makes this
    /// a test of the guard rather than a test of a marker file: a guard
    /// keyed on `setup_file.exists()` sees "no file, therefore generate"
    /// and silently replaces a password the operator has memorised, while
    /// reporting success. This test fails on that implementation and
    /// passes on the one that asks `passwd -S root`.
    #[test]
    fn a_password_the_operator_chose_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let setup_file = dir.path().join("root-console-password");
        assert!(!setup_file.exists(), "the fixture must start with no marker file");
        let seen = std::cell::RefCell::new(None::<String>);

        ensure_root_password_for(&setup_file, ROOT_HAS_ONE, |password| {
            *seen.borrow_mut() = Some(password.to_string());
            Ok(())
        })
        .unwrap();

        assert!(
            seen.into_inner().is_none(),
            "root already had a usable password and it was overwritten anyway"
        );
        assert!(
            !setup_file.exists(),
            "nothing should have been written: {:?}",
            std::fs::read_to_string(&setup_file)
        );
    }

    /// The write order, asserted from inside the setter.
    ///
    /// The plaintext must already be on disk by the time the account is
    /// changed, so a run killed between the two leaves root still
    /// password-less -- recoverable, because the next apply's guard says
    /// `L` and generates again. The inverse order is what made
    /// `ensure_first_authelia_user` produce a password that existed only
    /// in RAM.
    #[test]
    fn the_plaintext_is_on_disk_before_the_account_changes() {
        let dir = tempfile::tempdir().unwrap();
        let setup_file = dir.path().join("root-console-password");
        let probe = setup_file.clone();

        ensure_root_password_for(&setup_file, ROOT_LOCKED, move |password| {
            let content = std::fs::read_to_string(&probe).map_err(|e| {
                anyhow::anyhow!("the setup file was not readable when chpasswd ran: {e}")
            })?;
            assert_eq!(
                content,
                format!("{password}\n"),
                "the file must already hold this exact password before the account gets it"
            );
            Ok(())
        })
        .unwrap();
    }

    /// A failure applying the password leaves a file whose contents are
    /// not root's password -- and that is fine, because the guard still
    /// reports `L` and the next apply regenerates over it. Pinned so that
    /// nobody "fixes" it by writing the file last.
    ///
    /// The rewrite is the part that has actually broken: the first write
    /// leaves the file at `0400`, which is not writable, so reopening it
    /// fails for anyone without root's permission bypass. This test runs
    /// unprivileged in the Nix build sandbox and found exactly that, while
    /// the same test as root did not. The mode is re-asserted after the
    /// rewrite because `OpenOptions::mode` applies only at creation, so a
    /// reopen would have silently kept whatever mode was already there.
    #[test]
    fn a_failed_chpasswd_leaves_a_state_the_next_apply_can_recover_from() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let setup_file = dir.path().join("root-console-password");

        let err = ensure_root_password_for(&setup_file, ROOT_LOCKED, |_| {
            anyhow::bail!("chpasswd exploded")
        })
        .unwrap_err()
        .to_string();
        assert!(err.contains("chpasswd exploded"), "the real cause must surface: {err}");

        // The guard is unchanged by the failure, so the retry generates again.
        let seen = std::cell::RefCell::new(None::<String>);
        ensure_root_password_for(&setup_file, ROOT_LOCKED, |password| {
            *seen.borrow_mut() = Some(password.to_string());
            Ok(())
        })
        .unwrap();
        let applied = seen.into_inner().expect("the retry never called chpasswd");
        assert_eq!(std::fs::read_to_string(&setup_file).unwrap(), format!("{applied}\n"));
        let mode = std::fs::metadata(&setup_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "the rewrite did not restore root-only mode: {mode:o}");
    }

    /// Root-only from the instant it exists. A plaintext root password at
    /// umask-default mode, even briefly, is the window `write_first_user`
    /// already had to close.
    #[test]
    fn the_setup_file_is_root_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let setup_file = dir.path().join("root-console-password");
        write_root_password(&setup_file, "a-password").unwrap();
        let mode = std::fs::metadata(&setup_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "mode was {mode:o}");
    }

    /// Every status shadow can report, and every one it cannot.
    ///
    /// The unrecognised cases are errors rather than a default, because
    /// both available defaults are harmful: one strands the operator, the
    /// other destroys the credential they chose. `nobody P ...` is the
    /// specific accident this guards -- `passwd -S` with no argument
    /// reports on the calling user, and that answer says nothing about
    /// root.
    #[test]
    fn only_the_statuses_shadow_really_reports_are_understood() {
        assert!(root_needs_a_password(ROOT_LOCKED).unwrap());
        assert!(root_needs_a_password(ROOT_NO_PASSWORD).unwrap());
        assert!(!root_needs_a_password(ROOT_HAS_ONE).unwrap());
        // Bare two-field output, as some shadow builds print it.
        assert!(!root_needs_a_password("root P\n").unwrap());

        for bad in ["", "   \n", "root\n", "root PS 2026-09-30\n", "nobody P 2026-09-30\n"] {
            let err = match root_needs_a_password(bad) {
                Ok(answer) => panic!("{bad:?} was silently interpreted as needs-a-password={answer}"),
                Err(e) => e.to_string(),
            };
            assert!(
                err.contains("passwd -S root"),
                "the error must name what it could not read: {err}"
            );
        }
    }
}
