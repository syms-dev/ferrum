# Phase 1.5a — ferrumd (the daemon) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A real, working `ferrumd` — an unprivileged web daemon that can authenticate an operator, read/write `settings.json`, write operator-provided secrets, and trigger real privileged `ferrum-apply` runs through a polkit-authorized systemd mechanism, with live progress streamed back over SSE. No web UI yet (Phase 1.5b) — every capability here is exercisable by hand with `curl`.

**Architecture:** Six tasks. Task 1 extracts a shared `ferrum-secrets` library crate so `ferrum-apply` and the new `ferrumd` never duplicate the same zero-privilege sops-encrypt logic. Task 2 builds the privilege boundary itself (`ferrum-apply run-request` + the polkit-authorized systemd template unit) — the highest-risk, already-spiked mechanism — with nothing in `ferrumd` yet, so it's testable standalone. Tasks 3-5 build `ferrumd` itself: bootstrap/auth, the settings API, the secrets API. Task 6 is the capstone — the job API that actually calls the Task 2 mechanism, streams progress, and gets a full end-to-end NixOS VM test proving the whole chain works against a real `ferrum-testapp`-backed host, not a mock.

**Tech Stack:** Rust (`axum`/`tokio` for the web server, `zbus` for D-Bus, `rusqlite` for the job/session/user database, `argon2` for password hashing, `notify` for progress-file tailing), NixOS (`modules/core/daemon.nix`, `security.polkit.extraConfig`).

**Spec:** `docs/superpowers/specs/2026-08-21-phase-1-5a-daemon-design.md`.

## Global Constraints

- **Compromising ferrumd must only ever yield the power expressed by the settings schema, not arbitrary Nix evaluation as root.** `ferrum-apply run-request` (Task 2) accepts only a small fixed enum of request kinds mirroring its own existing five subcommands — it must never grow a way to pass arbitrary shell/Nix content through the request file.
- The privilege-boundary mechanism (polkit rule + systemd template unit + D-Bus `StartUnit` call) is **already empirically verified** on a real NixOS VM before this plan was written: a real unprivileged user, via a real `busctl` D-Bus call, successfully started a unit matching the polkit rule's regex and was denied starting any other unit. The exact rule text and unit-name pattern below are the real, tested values — transcribe them exactly.
- ferrumd's own auth is local-account-only, forever — never routed through Authelia, even once it exists for other apps (confirmed during brainstorming: ferrumd is how an operator bootstraps `ferrum.proxy`/`ferrum.auth` in the first place, so it cannot depend on either being configured).
- No default password, ever, for ferrumd's first account — the bootstrap flow (Task 3) generates a real random value and never bakes in a fixed one anywhere, including in tests.
- Secret values are never written into `settings.json`, and ferrumd never holds a private age key — every secret write (Task 5) goes through `ferrum_secrets::encrypt_and_write`, which needs only the host's public age recipient.
- `ferrum-apply`'s existing `ApplyResult` enum and exit-code convention (`crates/ferrum-apply/src/apply.rs:7-10`, `crates/ferrum-apply/src/main.rs`'s `handle_apply_result`) are the source of truth for job outcome — ferrumd classifies jobs by re-using these, never inventing a parallel vocabulary.
- `/var/lib/ferrum` stays on `@root`, never `@state` — already an asserted invariant in `modules/core/storage.nix`; this plan's new `/var/lib/ferrum/ferrumd.db` and `/var/lib/ferrum/jobs/` both live under that same existing, already-`@root`-guaranteed path.
- **Real dependency facts confirmed empirically before this plan was written** (not assumed from docs):
  - `zbus` 4.x: the `#[zbus::proxy(...)]` macro with `interface`/`default_service`/`default_path` attributes; `start_unit(&self, name: &str, mode: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>`; `#[zbus(signal)] fn job_removed(&self, id: u32, job: OwnedObjectPath, unit: String, result: String) -> zbus::Result<()>`. Confirmed via a real compiled, real-run program that made a genuine `StartUnit` D-Bus call and got back a real job path.
  - `axum` 0.7.x SSE: `axum::response::sse::{Event, Sse}`; `Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::new().interval(Duration::from_secs(15)))` where `stream: impl Stream<Item = Result<Event, Infallible>>`. Confirmed via a real compiled program.
  - `argon2` 0.5.x + `password-hash` 0.5.x **requires an explicit direct dependency on `rand_core = { version = "0.6", features = ["getrandom", "std"] }`** — without it, `argon2::password_hash::rand_core::OsRng` fails to resolve at compile time (`no OsRng in the root`, gated behind a feature that isn't enabled by transitive dependency alone). Confirmed by hitting this exact compile error and fixing it for real; the working `Cargo.toml` shape and the working hash/verify code are both below, transcribed from what actually compiled and ran.
  - `jsonschema` 0.18.x's real API is `jsonschema::JSONSchema::compile(&schema: &Value) -> Result<JSONSchema, ValidationError>`, then `.is_valid(&instance: &Value) -> bool` or `.validate(&instance: &Value) -> Result<(), ErrorIterator>` (an `ErrorIterator` yields real, human-readable `ValidationError`s — e.g. `"not-an-object" is not of type "object"` and `Additional properties are not allowed ('unexpected_field' was unexpected)`, both confirmed verbatim from a real run). **The version pin matters**: an unpinned `jsonschema = "0.18"` in `Cargo.toml` resolves to 0.18.3, whose real top-level API is `JSONSchema`/`compile`/`is_valid`/`validate` — NOT `jsonschema::validator_for(...)`, which is a newer (0.19+/0.20+, confirmed the registry offered 0.50.0 as latest) API shape that does not exist on 0.18.3 and fails with `error[E0425]: cannot find function 'validator_for' in crate 'jsonschema'`. This was hit for real while writing this plan and is why Task 4 pins the version and API calls exactly as verified below, rather than the more modern-looking `validator_for` name an implementer might otherwise reach for from newer docs or examples.

---

## Task 1: Extract `ferrum-secrets` — a shared library crate

**Files:**
- Create: `crates/ferrum-secrets/Cargo.toml`
- Create: `crates/ferrum-secrets/src/lib.rs`
- Modify: `crates/Cargo.toml` (add `ferrum-secrets` to workspace `members`)
- Modify: `crates/ferrum-apply/Cargo.toml` (add `ferrum-secrets` as a path dependency)
- Modify: `crates/ferrum-apply/src/secrets.rs` (remove the six moved functions/const, import them from `ferrum_secrets` instead)

**Interfaces:**
- Produces: `ferrum_secrets::{host_age_recipient, encrypt_and_write, random_hex_key, random_secret_value, base64_encode, rand_bytes, DEFAULT_HOST_KEY_PUB}` — all `pub`, consumed by `ferrum-apply` (this task) and later by `ferrumd` (Tasks 3/5).

- [ ] **Step 1: Write `crates/ferrum-secrets/Cargo.toml`**

```toml
[package]
name = "ferrum-secrets"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"

[dev-dependencies]
tempfile = "3"
```

- [ ] **Step 2: Write `crates/ferrum-secrets/src/lib.rs`**

This is `crates/ferrum-apply/src/secrets.rs`'s current top section (through `base64_encode`), moved verbatim with `pub` added to everything that needs to be callable from outside the crate. `encrypt_and_write`, `random_hex_key`, `rand_bytes`, and `base64_encode` are currently private (`fn`, not `pub fn`) in `ferrum-apply` — make all four `pub` here, since `ferrumd` (Task 5) needs `encrypt_and_write` directly and the others are its real dependencies.

```rust
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
```

- [ ] **Step 3: Wire the new crate into the workspace**

In `crates/Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["ferrum-apply", "ferrum-reconcile", "ferrum-secrets"]
```

In `crates/ferrum-apply/Cargo.toml`, add to `[dependencies]`:

```toml
ferrum-secrets = { path = "../ferrum-secrets" }
```

- [ ] **Step 4: Update `crates/ferrum-apply/src/secrets.rs` to use the shared crate**

Delete these six items from `secrets.rs` (they now live in `ferrum-secrets`): `DEFAULT_HOST_KEY_PUB`, `host_age_recipient`, `random_hex_key`, `rand_bytes`, `encrypt_and_write`, `random_secret_value`, `base64_encode` — and their six corresponding unit tests in `secrets.rs`'s own `mod tests` (`random_hex_key_is_32_lowercase_hex_chars`, `random_hex_key_is_not_constant`, `base64_encode_matches_rfc_4648_test_vector`, plus any test exercising `random_secret_value` directly) — those tests now live in `ferrum-secrets` (Step 2) instead.

At the top of `secrets.rs`, add:

```rust
use ferrum_secrets::{encrypt_and_write, host_age_recipient, random_hex_key, random_secret_value, DEFAULT_HOST_KEY_PUB};
```

Every remaining function in `secrets.rs` (`ensure_all`, `ensure_authelia_secrets`, `ensure_first_authelia_user`, `ensure_sabnzbd_apikey`, `argon2id_hash`) already calls these by their plain names (`host_age_recipient(...)`, `encrypt_and_write(...)`, etc.) — the `use` statement above is the only change needed for them to keep compiling unchanged. `main.rs`'s existing `secrets::DEFAULT_HOST_KEY_PUB` reference becomes invalid since the const moved; update `main.rs`'s one use site to `ferrum_secrets::DEFAULT_HOST_KEY_PUB` instead (add `use ferrum_secrets;` or reference it as `ferrum_secrets::DEFAULT_HOST_KEY_PUB` directly — `ferrum-apply`'s `Cargo.toml` already gained the dependency in Step 3).

- [ ] **Step 5: Real verification on ferrum-dev**

1. `cargo test --workspace --manifest-path crates/Cargo.toml` — every existing test across `ferrum-apply`/`ferrum-reconcile`/`ferrum-secrets` passes; the six relocated tests now run under `ferrum-secrets`, not `ferrum-apply`.
2. `cargo clippy --workspace --manifest-path crates/Cargo.toml --all-targets -- -D warnings` — clean (aside from the two already-known, already-documented pre-existing `apply.rs` failures unrelated to this task — confirm the diff doesn't touch those lines).
3. `nix build .#ferrum-apply` — succeeds, confirming the new workspace-internal path dependency resolves correctly under the Nix sandbox too, not just `cargo`.

- [ ] **Step 6: Commit**

```bash
git add crates/ferrum-secrets crates/Cargo.toml crates/ferrum-apply/Cargo.toml crates/ferrum-apply/src/secrets.rs crates/ferrum-apply/src/main.rs
git commit -m "Extract ferrum-secrets: a shared zero-privilege encryption library for ferrum-apply and the future ferrumd"
```

---

## Task 2: The privilege boundary — `ferrum-apply run-request` + the polkit-authorized systemd template unit

**Files:**
- Create: `crates/ferrum-apply/src/request.rs`
- Modify: `crates/ferrum-apply/src/main.rs` (new `RunRequest` subcommand)
- Create: `modules/core/daemon.nix`
- Modify: `modules/default.nix` (add the import)
- Create: `tests/privilege-boundary.nix`

**Interfaces:**
- Produces: `ferrum-apply run-request <path>` (a new CLI entry point onto the *existing* apply/rollback/preflight/restore-state/gc logic — no new privileged capability). The real, tested polkit rule and `ferrum-apply@.service` template unit shape, which Task 6's `ferrumd` will call into.
- Consumes: nothing new from earlier tasks.

- [ ] **Step 1: Write `crates/ferrum-apply/src/request.rs` — the request file schema and dispatch**

```rust
// The JSON request file format ferrumd (Phase 1.5a Task 6) writes and
// `ferrum-apply run-request` reads. Deliberately a small, closed enum --
// this is the entire privileged surface a compromised ferrumd could ever
// reach, so it must never grow a variant that accepts arbitrary shell/Nix
// content. Every variant maps onto a subcommand that already exists and
// is already tested; this file adds no new privileged LOGIC, only a new
// entry point onto it.
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    Preflight,
    Apply,
    Rollback { to: u32 },
    RestoreState,
    Gc,
}

pub fn read_request(path: &Path) -> anyhow::Result<Request> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read request file {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse request file {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apply_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"apply"}"#).unwrap();
        assert!(matches!(read_request(&path).unwrap(), Request::Apply));
    }

    #[test]
    fn parses_rollback_request_with_target_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"rollback","to":42}"#).unwrap();
        match read_request(&path).unwrap() {
            Request::Rollback { to } => assert_eq!(to, 42),
            other => panic!("expected Rollback, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"delete_everything"}"#).unwrap();
        assert!(read_request(&path).is_err(), "an unknown request kind must be rejected, never silently ignored");
    }

    #[test]
    fn rejects_malformed_json_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(read_request(&path).is_err());
    }
}
```

Add `serde = { version = "1", features = ["derive"] }` to `crates/ferrum-apply/Cargo.toml`'s `[dependencies]` if not already present (it already is, per the existing `Cargo.toml` — confirm rather than duplicate the line).

- [ ] **Step 2: Wire `run-request` into `main.rs`**

Add `mod request;` alongside the other `mod` declarations. Add a new `Command` variant:

```rust
    /// Read a JSON request file (written by ferrumd) and dispatch to the
    /// matching existing subcommand's logic. This is the ONLY entry point
    /// ferrumd itself ever triggers -- see modules/core/daemon.nix for the
    /// polkit rule and systemd template unit that authorize it.
    RunRequest {
        path: std::path::PathBuf,
    },
```

**This step is a mechanical extract-function refactor, not new logic.** Each existing `Command::Preflight`/`Command::Apply`/`Command::Rollback { to }`/`Command::RestoreState` arm in `main()`'s current `match cli.command` block already contains a real, working body (env-var reads plus a call into `preflight::run`/`apply::run`/`rollback::run`/etc., ending in `handle_apply_result` or an equivalent exit-code mapping) — read that exact existing code directly from the file before touching it. Move each arm's existing body, completely unchanged, into a same-named local function that returns the exit code as `i32` instead of being a match arm:

```rust
fn run_preflight() -> i32 { /* the existing Command::Preflight arm's body, moved verbatim, `return`s replaced with the trailing exit-code expression */ }
fn run_apply() -> i32 { /* the existing Command::Apply arm's body, moved verbatim */ }
fn run_rollback(to: u32) -> i32 { /* the existing Command::Rollback { to } arm's body, moved verbatim, using the `to` parameter in place of the arm's destructured `to` */ }
fn run_restore_state() -> i32 { /* the existing Command::RestoreState arm's body, moved verbatim */ }
```

Then both the original match arms and the new `RunRequest` arm call these functions instead of containing the logic inline:

```rust
        Command::Preflight => run_preflight(),
        Command::Apply => run_apply(),
        Command::Rollback { to } => run_rollback(to),
        Command::RestoreState => run_restore_state(),
        Command::Gc => { /* unchanged -- existing Gc arm body stays exactly as-is */ }
        Command::RunRequest { path } => match request::read_request(&path) {
            Ok(request::Request::Preflight) => run_preflight(),
            Ok(request::Request::Apply) => run_apply(),
            Ok(request::Request::Rollback { to }) => run_rollback(to),
            Ok(request::Request::RestoreState) => run_restore_state(),
            Ok(request::Request::Gc) => {
                eprintln!("gc: not yet implemented via run-request");
                1
            }
            Err(e) => {
                eprintln!("run-request: {e}");
                1
            }
        },
```

This refactor must not change any existing arm's behavior — it only relocates each body into a function so `RunRequest` can call the identical logic without duplicating it. Run `cargo test -p ferrum-apply` immediately after this step, before continuing, to confirm the four existing subcommand-parsing tests (`parses_preflight`, `parses_rollback_with_target_generation`, `parses_all_five_subcommands`, `apply_result_maps_to_distinct_exit_codes`) still pass unchanged — they exercise CLI parsing, not the relocated bodies, so a passing result here confirms the refactor didn't break argument handling, and the four functions' own logic should be spot-checked by hand against the pre-refactor `git diff` to confirm nothing changed except location.

Add three new tests to `main.rs`'s own `mod tests`:

```rust
    #[test]
    fn parses_run_request_subcommand() {
        let cli = Cli::parse_from(["ferrum-apply", "run-request", "/tmp/req.json"]);
        match cli.command {
            Command::RunRequest { path } => assert_eq!(path, std::path::PathBuf::from("/tmp/req.json")),
            other => panic!("expected RunRequest, got {other:?}"),
        }
    }
```

- [ ] **Step 3: Write `modules/core/daemon.nix` — the privilege boundary, no `ferrumd` unit yet (Task 6 adds that)**

```nix
# The ferrum system user and the privilege boundary that lets it trigger
# real ferrum-apply runs without ever becoming root itself. ferrumd's own
# systemd unit is NOT defined here -- that needs the ferrumd binary to
# exist first (Phase 1.5a Task 6). This file is deliberately testable and
# usable standalone: an operator (or a test) can already trigger a real
# apply via a real D-Bus call before ferrumd itself exists, which is
# exactly what tests/privilege-boundary.nix does.
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
in
lib.mkIf ferrum.daemon.enable {
  users.users.ferrum = {
    isSystemUser = true;
    group = "ferrum";
    description = "ferrumd -- the unprivileged ferrum web daemon";
  };
  users.groups.ferrum = { };

  # Real, tested rule -- confirmed for real on ferrum-dev with a genuine
  # unprivileged D-Bus StartUnit call: a real "ferrum-apply@<uuid>.service"
  # start succeeded, a real "sshd.service" start was denied. The 36-char
  # class matches a standard UUID string (8-4-4-4-12 hex digits, 4
  # hyphens) -- ferrumd (Task 6) generates the UUID per job request; it is
  # NEVER parsed as data by this rule or by ferrum-apply itself, only
  # compared against this fixed pattern.
  security.polkit.enable = true;
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "org.freedesktop.systemd1.manage-units" &&
          action.lookup("unit") &&
          /^ferrum-apply@[0-9a-f-]{36}\.service$/.test(action.lookup("unit")) &&
          action.lookup("verb") == "start") {
        return polkit.Result.YES;
      }
    });
  '';

  systemd.services."ferrum-apply@" = {
    description = "ferrum-apply, dispatched from a ferrumd-written request file";
    serviceConfig = {
      Type = "oneshot";
      # %i is systemd's own instance-name substitution -- the UUID from
      # the unit's own instance name becomes part of the request file
      # PATH here, never re-interpreted as a command or shell content.
      # /run/ferrum is tmpfs, root-readable regardless of the file's own
      # mode (root bypasses permission checks entirely), so ferrumd (Task
      # 6) needs no special permission dance beyond the directory being
      # writable by the ferrum user.
      ExecStart = "${pkgs.ferrum-apply}/bin/ferrum-apply run-request /run/ferrum/requests/%i.json";
    };
  };

  systemd.tmpfiles.rules = [
    "d /run/ferrum/requests 0750 ferrum ferrum - -"
  ];

  # /etc/ferrum's own carved-out permission model (settings.json and
  # secrets/ writable by ferrumd, everything else root-only) is provisioned
  # once by nixos-anywhere's own initial setup, not by this module at
  # runtime -- this only ASSERTS the expected shape exists before ferrumd
  # is allowed to start, mirroring modules/core/storage.nix's own
  # assertion style, so a host provisioned before this phase existed fails
  # loud with an actionable message instead of ferrumd silently failing to
  # write settings.json the first time an operator tries.
  assertions = [
    {
      assertion = builtins.pathExists /etc/ferrum/settings.json;
      message = ''
        ferrum.daemon.enable is true but /etc/ferrum/settings.json does not
        exist. This file must be provisioned once, at creation, owned
        root:ferrum mode 0664, as part of this host's initial
        nixos-anywhere setup -- ferrumd itself never creates it.
      '';
    }
    {
      assertion = builtins.pathExists /etc/ferrum/secrets;
      message = ''
        ferrum.daemon.enable is true but /etc/ferrum/secrets does not
        exist. This directory must be provisioned once, at creation, owned
        ferrum:ferrum mode 0750, as part of this host's initial
        nixos-anywhere setup.
      '';
    }
  ];
}
```

- [ ] **Step 4: Wire the module into `modules/default.nix`**

Add `./core/daemon.nix` to the `imports` list, alongside the other `./core/*.nix` entries.

- [ ] **Step 5: Write `tests/privilege-boundary.nix` — the real, empirical proof this mechanism works against the REAL ferrum-apply binary**

This mirrors the spike already run while writing this plan, but targets the real `ferrum-apply run-request` dispatch instead of a `touch` stub, and a real unprivileged test user matching ferrumd's own posture.

```nix
{ pkgs }:
pkgs.testers.runNixOSTest {
  name = "privilege-boundary";
  nodes.machine = { config, lib, pkgs, ... }: {
    imports = [ (../modules/core/daemon.nix) ];
    options.ferrum = lib.mkOption { type = lib.types.raw; default = { }; };
    config = {
      ferrum.daemon.enable = true;
      # Satisfy the two assertions Step 3 added, since this test doesn't
      # go through real nixos-anywhere provisioning.
      systemd.tmpfiles.rules = [
        "f /etc/ferrum/settings.json 0664 root ferrum - {}"
        "d /etc/ferrum/secrets 0750 ferrum ferrum - -"
      ];
      users.users.testferrum = {
        isNormalUser = true;
      };
      system.stateVersion = "25.11";
    };
  };
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("polkit.service")

    valid_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    # A real request file, written as root here to simulate what ferrumd
    # (Task 6) will do for real -- this test's job is the privilege
    # boundary, not ferrumd itself.
    machine.succeed(
        f"mkdir -p /run/ferrum/requests && "
        f"echo '{{\"kind\":\"preflight\"}}' > /run/ferrum/requests/{valid_uuid}.json && "
        f"chown ferrum:ferrum /run/ferrum/requests/{valid_uuid}.json"
    )

    print("=== unprivileged user triggers a REAL ferrum-apply run-request via D-Bus ===")
    machine.succeed(
        f"su - testferrum -c \\"busctl call --system org.freedesktop.systemd1 "
        f"/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "
        f"'ferrum-apply@{valid_uuid}.service' replace\\""
    )
    machine.wait_until_succeeds(
        f"systemctl show ferrum-apply@{valid_uuid}.service -p Result | grep -q 'Result=success'"
    )
    print("PASS: the real ferrum-apply binary really ran preflight, dispatched through the real polkit+D-Bus mechanism")

    print("=== unprivileged user tries an unrelated unit -- must be denied ===")
    machine.fail(
        "su - testferrum -c \\"busctl call --system org.freedesktop.systemd1 "
        "/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "
        "'sshd.service' replace\\""
    )
    print("PASS: starting an unrelated unit was correctly denied")
  '';
}
```

Wire it into `nix/modules/flake/checks.nix` alongside the other VM tests: `privilege-boundary = import ../../../tests/privilege-boundary.nix { inherit pkgs; };`.

- [ ] **Step 6: Real verification on ferrum-dev**

1. `cargo test -p ferrum-apply` — new `request.rs` tests plus the new `parses_run_request_subcommand` test all pass; existing tests unaffected.
2. `cargo clippy -p ferrum-apply --all-targets -- -D warnings` — clean.
3. Real `nix eval` of a host with `ferrum.daemon.enable = true` (and the two assertion-satisfying stub files/dirs) — confirms the module evaluates cleanly, the polkit rule text is syntactically valid JS (polkit rules are evaluated, not just stored as a string), and the template unit resolves `${pkgs.ferrum-apply}` correctly.
4. `nix build .#checks.x86_64-linux.privilege-boundary --print-build-logs` — the real VM test from Step 5 passes both assertions.

- [ ] **Step 7: Commit**

```bash
git add crates/ferrum-apply/src/request.rs crates/ferrum-apply/src/main.rs modules/core/daemon.nix modules/default.nix tests/privilege-boundary.nix nix/modules/flake/checks.nix
git commit -m "Add the privilege boundary: ferrum-apply run-request, the polkit rule, and the ferrum-apply@ template unit"
```

---

## Task 3: `ferrumd` bootstrap — SQLite schema, first-user setup, login/session/CSRF/rate-limiting

**Files:**
- Create: `crates/ferrumd/Cargo.toml`
- Create: `crates/ferrumd/src/main.rs`
- Create: `crates/ferrumd/src/db.rs`
- Create: `crates/ferrumd/src/auth.rs`
- Modify: `crates/Cargo.toml` (add `ferrumd` to workspace `members`)

**Interfaces:**
- Consumes: `ferrum_secrets::random_secret_value` (Task 1) for the bootstrap password.
- Produces: `db::Db` (a thin `rusqlite::Connection` wrapper, consumed by Tasks 4/5/6), `auth::{require_session, login_handler, logout_handler}` (axum middleware/handlers, consumed by Tasks 4/5/6's own routes), the `/var/lib/ferrum/ferrumd.db` schema (`users`, `sessions`, `login_attempts` tables now; `jobs` added in Task 6).

- [ ] **Step 1: Write `crates/ferrumd/Cargo.toml`**

```toml
[package]
name = "ferrumd"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "ferrumd"
path = "src/main.rs"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
rusqlite = { version = "0.31", features = ["bundled"] }
argon2 = "0.5"
password-hash = "0.5"
rand_core = { version = "0.6", features = ["getrandom", "std"] }
tower-cookies = "0.10"
ferrum-secrets = { path = "../ferrum-secrets" }

[dev-dependencies]
tempfile = "3"
```

(`rusqlite`'s `bundled` feature compiles SQLite from source rather than linking a system library -- the right choice here since `nix build` sandboxes have no guaranteed system `libsqlite3`, matching how `rustPlatform.buildRustPackage` already handles `ferrum-apply`/`ferrum-reconcile` with zero extra `nativeBuildInputs` for their own dependencies.)

- [ ] **Step 2: Write `crates/ferrumd/src/db.rs` — schema and connection**

```rust
// ferrumd's own SQLite database at /var/lib/ferrum/ferrumd.db (on @root,
// per modules/core/storage.nix's existing invariant -- this file never
// creates that directory itself, it's provisioned the same way
// /var/lib/ferrum already is for ferrum-apply's own journal).
use rusqlite::Connection;
use std::path::Path;

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| anyhow::anyhow!("failed to open ferrumd database at {}: {e}", path.display()))?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                csrf_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                succeeded INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_all_three_tables() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('users','sessions','login_attempts')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn open_is_idempotent_against_an_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        Db::open(&path).unwrap();
        let result = Db::open(&path);
        assert!(result.is_ok(), "opening an already-initialized database must not fail: {result:?}");
    }
}
```

- [ ] **Step 3: Write `crates/ferrumd/src/auth.rs` — first-user bootstrap, login, sessions, CSRF, rate limiting**

```rust
// Local-account auth, forever -- see the plan's Global Constraints for why
// this never routes through Authelia. First-run bootstrap happens HERE,
// inside ferrumd's own startup, not via ferrum-apply -- unlike Authelia's
// own bootstrap (Phase 1.4b), which needed the privileged pre-build step
// because Authelia's user database has to exist before Authelia's own
// systemd unit starts, ferrumd's user table lives inside ferrumd's own
// already-owned database in its own already-owned state directory. No
// privilege or cross-crate coupling is needed for this.
use crate::db::Db;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const SETUP_PASSWORD_FILE: &str = "authelia-setup-password"; // placeholder name, see note below
const SESSION_LIFETIME_SECS: i64 = 60 * 60 * 24 * 7; // one week
const MAX_FAILURES_PER_WINDOW: i64 = 5;
const RATE_LIMIT_WINDOW_SECS: i64 = 300; // 5 minutes
const LOCKOUT_SECS: i64 = 60;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Idempotent: does nothing if any user already exists, so a ferrumd
/// restart never resets an operator's already-changed password. Mirrors
/// ensure_first_authelia_user's exact shape (crates/ferrum-apply/src/
/// secrets.rs) -- same "generate real random value, write plaintext once
/// to a root-only 0400 file, hash the rest" pattern, just running inside
/// ferrumd's own process instead of ferrum-apply's.
pub fn ensure_first_user(db: &Db, state_dir: &Path) -> anyhow::Result<()> {
    let existing: i64 = db.conn().query_row("SELECT count(*) FROM users", [], |row| row.get(0))?;
    if existing > 0 {
        return Ok(());
    }

    let password = ferrum_secrets::random_secret_value()?;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash bootstrap password: {e}"))?
        .to_string();

    db.conn().execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES ('admin', ?1, ?2)",
        rusqlite::params![hash, now()],
    )?;

    let setup_file = state_dir.join("ferrumd-setup-password");
    std::fs::create_dir_all(state_dir)?;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(&setup_file)?;
    f.write_all(format!("{password}\n").as_bytes())?;
    Ok(())
}

pub struct LoginResult {
    pub session_token: String,
    pub csrf_token: String,
}

/// Real argon2id verification against the stored hash, with rate limiting
/// checked BEFORE the (comparatively expensive) hash verification runs --
/// a locked-out username never even reaches argon2, so a lockout can't
/// itself become a CPU-exhaustion vector.
pub fn login(db: &Db, username: &str, password: &str) -> anyhow::Result<Option<LoginResult>> {
    let window_start = now() - RATE_LIMIT_WINDOW_SECS;
    let recent_failures: i64 = db.conn().query_row(
        "SELECT count(*) FROM login_attempts WHERE username = ?1 AND succeeded = 0 AND attempted_at > ?2",
        rusqlite::params![username, window_start],
        |row| row.get(0),
    )?;
    if recent_failures >= MAX_FAILURES_PER_WINDOW {
        let last_attempt: i64 = db.conn().query_row(
            "SELECT max(attempted_at) FROM login_attempts WHERE username = ?1",
            rusqlite::params![username],
            |row| row.get(0),
        )?;
        if now() - last_attempt < LOCKOUT_SECS {
            anyhow::bail!("too many failed login attempts -- try again shortly");
        }
    }

    let row: Option<(i64, String)> = db
        .conn()
        .query_row(
            "SELECT id, password_hash FROM users WHERE username = ?1",
            rusqlite::params![username],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let succeeded = match &row {
        Some((_, hash)) => {
            let parsed = PasswordHash::new(hash)
                .map_err(|e| anyhow::anyhow!("stored password hash is corrupt: {e}"))?;
            Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
        }
        None => false,
    };

    db.conn().execute(
        "INSERT INTO login_attempts (username, attempted_at, succeeded) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, now(), succeeded as i64],
    )?;

    if !succeeded {
        return Ok(None);
    }
    let (user_id, _) = row.expect("succeeded implies row was Some");

    let session_token = ferrum_secrets::random_secret_value()?;
    let csrf_token = ferrum_secrets::random_secret_value()?;
    db.conn().execute(
        "INSERT INTO sessions (token, user_id, csrf_token, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![session_token, user_id, csrf_token, now(), now() + SESSION_LIFETIME_SECS],
    )?;

    Ok(Some(LoginResult { session_token, csrf_token }))
}

/// Returns the session's own CSRF token if `token` is a real, unexpired
/// session -- callers use this both to authenticate a request AND to
/// validate the CSRF header on mutating requests against the SAME lookup,
/// rather than two separate queries that could disagree.
pub fn validate_session(db: &Db, token: &str) -> anyhow::Result<Option<String>> {
    db.conn()
        .query_row(
            "SELECT csrf_token FROM sessions WHERE token = ?1 AND expires_at > ?2",
            rusqlite::params![token, now()],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e.into()) })
}

pub fn logout(db: &Db, token: &str) -> anyhow::Result<()> {
    db.conn().execute("DELETE FROM sessions WHERE token = ?1", rusqlite::params![token])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn ensure_first_user_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let count_after_first: i64 = db.conn().query_row("SELECT count(*) FROM users", [], |r| r.get(0)).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let count_after_second: i64 = db.conn().query_row("SELECT count(*) FROM users", [], |r| r.get(0)).unwrap();
        assert_eq!(count_after_first, 1);
        assert_eq!(count_after_first, count_after_second, "a second call must not add a second user or reset the password");
    }

    #[test]
    fn login_succeeds_with_the_real_bootstrap_password() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let password = password.trim();
        let result = login(&db, "admin", password).unwrap();
        assert!(result.is_some(), "login with the real generated password must succeed");
    }

    #[test]
    fn login_fails_with_the_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let result = login(&db, "admin", "definitely-wrong").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn login_locks_out_after_five_failures_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        for _ in 0..5 {
            let _ = login(&db, "admin", "wrong").unwrap();
        }
        let result = login(&db, "admin", "wrong");
        assert!(result.is_err(), "the 6th attempt within the window must be rejected outright, not just fail auth");
    }

    #[test]
    fn validate_session_returns_none_for_an_unknown_token() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        assert_eq!(validate_session(&db, "not-a-real-token").unwrap(), None);
    }

    #[test]
    fn logout_invalidates_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let login_result = login(&db, "admin", password.trim()).unwrap().unwrap();
        assert!(validate_session(&db, &login_result.session_token).unwrap().is_some());
        logout(&db, &login_result.session_token).unwrap();
        assert_eq!(validate_session(&db, &login_result.session_token).unwrap(), None);
    }
}
```

**Note on `SETUP_PASSWORD_FILE`:** the constant declared at the top is unused dead code left over from drafting -- remove it; the real filename (`"ferrumd-setup-password"`) is inlined directly in `ensure_first_user` above. Flagging this explicitly so the implementer removes it rather than transcribing an unused `const` that `clippy -D warnings` would flag.

- [ ] **Step 4: Write `crates/ferrumd/src/main.rs` — server bootstrap, login/logout HTTP handlers**

```rust
mod auth;
mod db;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

pub struct AppState {
    pub db: db::Db,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    csrf_token: String,
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    match auth::login(&state.db, &req.username, &req.password) {
        Ok(Some(result)) => {
            let mut cookie = Cookie::new("ferrumd_session", result.session_token);
            cookie.set_http_only(true);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            cookie.set_path("/");
            cookies.add(cookie);
            (StatusCode::OK, Json(LoginResponse { csrf_token: result.csrf_token })).into_response()
        }
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => (StatusCode::TOO_MANY_REQUESTS, e.to_string()).into_response(),
    }
}

async fn logout_handler(State(state): State<Arc<AppState>>, cookies: Cookies) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("ferrumd_session") {
        let _ = auth::logout(&state.db, cookie.value());
    }
    cookies.remove(Cookie::new("ferrumd_session", ""));
    StatusCode::OK
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let state_dir = std::env::var("FERRUMD_STATE_DIR").unwrap_or_else(|_| "/var/lib/ferrum".to_string());
    let state_dir = std::path::Path::new(&state_dir);
    let db = db::Db::open(&state_dir.join("ferrumd.db"))?;
    auth::ensure_first_user(&db, state_dir)?;

    let state = Arc::new(AppState { db });
    let app = Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listen_address = std::env::var("FERRUMD_LISTEN_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("FERRUMD_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(7788);
    let listener = tokio::net::TcpListener::bind(format!("{listen_address}:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 5: Wire the new crate into the workspace**

In `crates/Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["ferrum-apply", "ferrum-reconcile", "ferrum-secrets", "ferrumd"]
```

- [ ] **Step 6: Real verification on ferrum-dev**

1. `cargo test -p ferrumd` — all 7 new tests across `db.rs`/`auth.rs` pass.
2. `cargo clippy -p ferrumd --all-targets -- -D warnings` — clean, and specifically confirm the unused `SETUP_PASSWORD_FILE` const (noted above) was actually removed, not left in.
3. `cargo build -p ferrumd` then real manual exercise: run the built binary with `FERRUMD_STATE_DIR=/tmp/ferrumd-test`, confirm `/tmp/ferrumd-test/ferrumd-setup-password` is created with real content and mode `0400`, then `curl -X POST http://127.0.0.1:7788/api/login -d '{"username":"admin","password":"<the real content>"}' -H 'Content-Type: application/json'` returns `200` with a real `csrf_token` and sets a real `ferrumd_session` cookie; a wrong password returns `401`; six wrong attempts in a row return `429` on the sixth.

- [ ] **Step 7: Commit**

```bash
git add crates/ferrumd crates/Cargo.toml
git commit -m "Add ferrumd bootstrap: SQLite schema, first-user setup, login/session/CSRF/rate-limiting"
```

---

## Task 4: Settings API

**Files:**
- Create: `modules/lib/settings-schema.json`
- Modify: `nix/overlays/default.nix` (add `ferrum-settings-schema` — this is what makes `pkgs.ferrum-settings-schema` resolve inside a NixOS module; `packages.nix` alone does NOT, confirmed by reading the real overlay file, which currently carries only `ferrum-apply`/`ferrum-reconcile`/`ferrum-testapp` and is the single thing `modules/core/overlays.nix` wires into `nixpkgs.overlays` for host evaluation)
- Modify: `nix/modules/flake/packages.nix` (add the `ferrum-settings-schema` package, for direct `nix build .#ferrum-settings-schema` — mirrors the existing `ferrum-catalog`/`ferrum-apply`/`ferrum-reconcile` entries, which are each declared in both places)
- Create: `crates/ferrumd/src/settings.rs`
- Modify: `crates/ferrumd/src/main.rs` (wire the new routes, add session-auth middleware)

**Interfaces:**
- Consumes: `auth::validate_session` (Task 3).
- Produces: `GET /api/settings`, `PUT /api/settings` (consumed by nothing yet in this plan — the future Phase 1.5b UI is the real consumer). The `ferrum-settings-schema` package, consumed by Task 6's `modules/core/daemon.nix` wiring.

**Real correction made while writing this plan:** the original design doc describes "a hand-written JSON Schema for the whole `ferrum.*` document" as something Nix builds — but the real, current `ferrum-catalog` package (`nix/modules/flake/packages.nix:13-21`, confirmed by reading it directly) only emits `{schemaVersion, ferrumVersion, apps}` — per-app catalog *metadata*, not a JSON-Schema-shaped document usable with `jsonschema::JSONSchema::compile`. No settings JSON Schema exists anywhere in the codebase yet. Step 1 below creates the missing hand-written schema as real, necessary scope for this task, matching `options.ferrum`'s actual current shape (verified directly against `modules/core/options.nix`, not assumed) — deferring only the dynamic, catalog-driven `apps` submodule's own deep validation, which is out of Phase 1.5a's stated scope (the daemon backend, not full schema fidelity for the future UI).

- [ ] **Step 1: Write `modules/lib/settings-schema.json` and package it**

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "schemaVersion": { "type": "integer" },
    "storage": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "stateDir": { "type": "string" },
        "snapshotDir": { "type": "string" },
        "journalDir": { "type": "string" },
        "mediaDir": { "type": "string" },
        "mediaGroup": { "type": "string" },
        "minFreeGiB": { "type": "integer" },
        "keepGenerations": { "type": "integer" }
      }
    },
    "secretsDir": { "type": "string" },
    "proxy": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enable": { "type": "boolean" },
        "baseDomain": { "type": "string" },
        "acme": {
          "type": "object",
          "additionalProperties": false,
          "properties": {
            "email": { "type": "string" },
            "dnsProvider": { "type": "string", "enum": ["cloudflare"] },
            "credentialSecret": { "type": "string" },
            "staging": { "type": "boolean" }
          }
        },
        "trustedNetworks": { "type": "array", "items": { "type": "string" } }
      }
    },
    "auth": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enable": { "type": "boolean" },
        "adminEmail": { "type": "string" }
      }
    },
    "recyclarr": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enable": { "type": "boolean" }
      }
    },
    "secrets": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "description": { "type": "string" }
        }
      }
    },
    "backup": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enable": { "type": "boolean" },
        "repo": { "type": "string" },
        "schedule": { "type": "string" },
        "passwordSecret": { "type": "string" }
      }
    },
    "apply": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "autoRollbackOnFailure": { "type": "boolean" },
        "healthCheckTimeoutSec": { "type": "integer" }
      }
    },
    "daemon": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "enable": { "type": "boolean" },
        "port": { "type": "integer" },
        "listenAddress": { "type": "string" },
        "subdomain": { "type": "string" }
      }
    },
    "apps": {
      "type": "object",
      "description": "Per-app settings, keyed by catalog app name. Deep per-app validation is deferred -- Phase 1.5a's own scope is the daemon backend; a future task tightens this against the real catalog-driven submodule shape."
    }
  }
}
```

This must stay hand-maintained in sync with `modules/core/options.nix`'s real shape — the existing `checks.schema-uniformity` (`nix/modules/flake/checks.nix`) already asserts every `ferrum.*` option type is JSON-expressible, but does not generate this file automatically; keeping the two in sync by hand, with `schema-uniformity` as the mechanical backstop against an option type drifting out of JSON-expressibility, matches this codebase's existing pattern rather than inventing a new one.

Add the package to `nix/overlays/default.nix` first — this is the entry that actually makes `pkgs.ferrum-settings-schema` resolve inside `modules/core/daemon.nix` (Task 6):

```nix
final: prev: {
  ferrum-apply = final.callPackage ../pkgs/ferrum-apply { };
  ferrum-reconcile = final.callPackage ../pkgs/ferrum-reconcile { };
  ferrum-testapp = final.callPackage ../pkgs/testapp { };
  ferrum-settings-schema = final.writeTextFile {
    name = "ferrum-settings-schema.json";
    destination = "/share/ferrum/settings-schema.json";
    text = builtins.readFile ../../modules/lib/settings-schema.json;
  };
}
```

Then add the matching entry to `nix/modules/flake/packages.nix`'s `packages` attrset, alongside the existing `ferrum-catalog` entry, for direct `nix build .#ferrum-settings-schema` access:

```nix
        ferrum-settings-schema = pkgs.writeTextFile {
          name = "ferrum-settings-schema.json";
          destination = "/share/ferrum/settings-schema.json";
          text = builtins.readFile ../../../modules/lib/settings-schema.json;
        };
```

- [ ] **Step 2: Write `crates/ferrumd/src/settings.rs`**

```rust
// Settings read/write. PUT never triggers an apply -- that's always a
// separate, explicit POST /api/jobs call (Task 6), so an operator reviews
// a change before it's ever built. Schema validation happens against
// $FERRUM_SETTINGS_SCHEMA (the ferrum-settings-schema package built in
// this task's own Step 1), which is necessarily a snapshot from the last
// rebuild: a brand-new option only validates once the box has already
// rebuilt with it, exactly the same rebuild that app's own service.nix
// needs to exist at all.
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::Value;
use std::sync::Arc;

use crate::AppState;

fn settings_path() -> std::path::PathBuf {
    std::env::var("FERRUM_SETTINGS_PATH")
        .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string())
        .into()
}

pub async fn get_settings() -> impl IntoResponse {
    match std::fs::read_to_string(settings_path()) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(parsed) => (StatusCode::OK, Json(parsed)).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("settings.json is corrupt: {e}")).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read settings.json: {e}")).into_response(),
    }
}

/// Real, verified API (see this plan's Global Constraints for the exact
/// jsonschema 0.18.3 facts, confirmed via a real compiled spike --
/// including the version-pin gotcha that an unpinned "0.18" would silently
/// resolve fine but a NEWER jsonschema major uses a different top-level
/// function name entirely). Compiling the schema on every request is
/// deliberate, not an oversight: $FERRUM_SETTINGS_SCHEMA's own file can
/// change between requests only via a full host rebuild, which always
/// restarts ferrumd (systemd unit dependency, Task 6 Step 6) -- so
/// re-reading it fresh each call is simpler than cache invalidation and
/// costs one file read plus a schema compile per settings write, not per
/// read.
fn validate_against_schema(proposed: &Value) -> Result<(), String> {
    let schema_path = std::env::var("FERRUM_SETTINGS_SCHEMA")
        .map_err(|_| "FERRUM_SETTINGS_SCHEMA not set -- cannot validate settings".to_string())?;
    let schema_raw = std::fs::read_to_string(&schema_path)
        .map_err(|e| format!("failed to read settings schema at {schema_path}: {e}"))?;
    let schema: Value = serde_json::from_str(&schema_raw)
        .map_err(|e| format!("settings schema at {schema_path} is not valid JSON: {e}"))?;
    let compiled = jsonschema::JSONSchema::compile(&schema)
        .map_err(|e| format!("settings schema at {schema_path} does not compile as JSON Schema: {e}"))?;
    match compiled.validate(proposed) {
        Ok(()) => Ok(()),
        Err(errors) => {
            let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            Err(format!("settings failed schema validation: {}", messages.join("; ")))
        }
    }
}

pub async fn put_settings(
    State(_state): State<Arc<AppState>>,
    Json(proposed): Json<Value>,
) -> impl IntoResponse {
    if let Err(msg) = validate_against_schema(&proposed) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    let path = settings_path();
    let content = serde_json::to_string_pretty(&proposed).unwrap();
    match std::fs::write(&path, content) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write settings.json: {e}")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_against_schema_rejects_when_env_var_unset() {
        std::env::remove_var("FERRUM_SETTINGS_SCHEMA");
        let result = validate_against_schema(&serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FERRUM_SETTINGS_SCHEMA not set"));
    }

    #[test]
    fn validate_against_schema_accepts_a_conforming_document() {
        let dir = tempfile::tempdir().unwrap();
        let schema_path = dir.path().join("settings-schema.json");
        std::fs::write(&schema_path, serde_json::json!({
            "type": "object",
            "properties": { "secrets": { "type": "object" } },
            "required": ["secrets"]
        }).to_string()).unwrap();
        std::env::set_var("FERRUM_SETTINGS_SCHEMA", &schema_path);
        let result = validate_against_schema(&serde_json::json!({"secrets": {}}));
        assert!(result.is_ok(), "expected a conforming document to pass: {result:?}");
    }

    #[test]
    fn validate_against_schema_rejects_a_nonconforming_document() {
        let dir = tempfile::tempdir().unwrap();
        let schema_path = dir.path().join("settings-schema.json");
        std::fs::write(&schema_path, serde_json::json!({
            "type": "object",
            "properties": { "secrets": { "type": "object" } },
            "required": ["secrets"]
        }).to_string()).unwrap();
        std::env::set_var("FERRUM_SETTINGS_SCHEMA", &schema_path);
        let result = validate_against_schema(&serde_json::json!({"secrets": "not-an-object"}));
        assert!(result.is_err(), "expected a type mismatch to fail validation");
    }
}
```

Add `jsonschema = "0.18"` to `crates/ferrumd/Cargo.toml`'s `[dependencies]` — pinned to the `0.18` line specifically, matching the real, verified API above (a newer major resolves to a different top-level function name, per this plan's Global Constraints).

- [ ] **Step 3: Wire the routes and session-auth middleware into `main.rs`**

Add a small auth-checking extractor/middleware — axum's `axum::middleware::from_fn_with_state` is the standard mechanism:

```rust
async fn require_session(
    State(state): State<Arc<AppState>>,
    cookies: tower_cookies::Cookies,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let token = cookies.get("ferrumd_session").ok_or(StatusCode::UNAUTHORIZED)?;
    match auth::validate_session(&state.db, token.value()) {
        Ok(Some(_csrf)) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
```

In `main()`'s `Router` construction, add the settings routes behind this middleware, mirroring axum's own established `route_layer`/nested-router pattern for "these routes need auth, these don't":

```rust
    let protected = Router::new()
        .route("/api/settings", axum::routing::get(settings::get_settings).put(settings::put_settings))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_session));

    let app = Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .merge(protected)
        .layer(CookieManagerLayer::new())
        .with_state(state);
```

Add `mod settings;` to `main.rs`'s module declarations.

- [ ] **Step 4: Real verification on ferrum-dev**

1. `cargo test -p ferrumd` — the three new `validate_against_schema` tests pass.
2. `cargo build -p ferrumd` — compiles.
3. `nix build .#ferrum-settings-schema` — the new package (Step 1) builds; confirm `result/share/ferrum/settings-schema.json` contains the real schema content and is valid JSON.
4. Manual exercise, with `FERRUM_SETTINGS_SCHEMA` pointed at the real built package's output: `GET /api/settings` without a session cookie returns `401`; with a valid session cookie (from a real login, Task 3) returns `200` with the real current `settings.json` content; `PUT /api/settings` with a valid session and a document that conforms to the real schema updates the file (confirm via a subsequent `GET` or reading the file directly) but does NOT trigger any `ferrum-apply` process (confirm via `ps`/`systemctl` — no new unit started); a `PUT` with a document that violates the real schema (e.g. `secrets` as a string instead of an object) returns `400` with a real, specific error message and leaves `settings.json` unchanged.

- [ ] **Step 5: Commit**

```bash
git add modules/lib/settings-schema.json nix/overlays/default.nix nix/modules/flake/packages.nix crates/ferrumd/src/settings.rs crates/ferrumd/src/main.rs crates/ferrumd/Cargo.toml
git commit -m "Add the settings API: GET/PUT /api/settings, real JSON Schema validation against a new hand-written ferrum-settings-schema package"
```

---

## Task 5: Secrets API

**Files:**
- Create: `crates/ferrumd/src/secrets_api.rs`
- Modify: `crates/ferrumd/src/main.rs` (wire the new route)

**Interfaces:**
- Consumes: `ferrum_secrets::{host_age_recipient, encrypt_and_write}` (Task 1), `auth`/`require_session` (Tasks 3/4).
- Produces: `POST /api/secrets/:name`.

- [ ] **Step 1: Write `crates/ferrumd/src/secrets_api.rs`**

```rust
// Write-only, by construction: there is deliberately no GET handler
// anywhere in this file, and never will be -- that's what makes "ferrumd
// can write any secret but cannot read one back" a structural property,
// not a policy someone has to remember to uphold.
use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::Value;

fn secrets_dir() -> std::path::PathBuf {
    std::env::var("FERRUM_SECRETS_DIR").unwrap_or_else(|_| "/etc/ferrum/secrets".to_string()).into()
}

fn host_key_pub() -> std::path::PathBuf {
    std::env::var("FERRUM_HOST_KEY_PUB")
        .unwrap_or_else(|_| ferrum_secrets::DEFAULT_HOST_KEY_PUB.to_string())
        .into()
}

/// `name` is only accepted when the current settings.json's own
/// `ferrum.secrets` map declares it -- an arbitrary name is rejected,
/// keeping the write surface catalog/settings-driven rather than an
/// open-ended file-write primitive.
fn is_declared_secret(name: &str) -> anyhow::Result<bool> {
    let settings_path = std::env::var("FERRUM_SETTINGS_PATH").unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
    let raw = std::fs::read_to_string(&settings_path)?;
    let parsed: Value = serde_json::from_str(&raw)?;
    Ok(parsed
        .get("secrets")
        .and_then(|s| s.as_object())
        .map(|obj| obj.contains_key(name))
        .unwrap_or(false))
}

pub async fn write_secret(Path(name): Path<String>, body: Bytes) -> impl IntoResponse {
    match is_declared_secret(&name) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::BAD_REQUEST, format!("'{name}' is not declared in ferrum.secrets")).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to check ferrum.secrets: {e}")).into_response(),
    }

    let plaintext = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "secret value must be valid UTF-8").into_response(),
    };

    let recipient = match ferrum_secrets::host_age_recipient(&host_key_pub()) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to derive host age recipient: {e}")).into_response(),
    };

    let dest = secrets_dir().join(format!("{name}.sops"));
    match ferrum_secrets::encrypt_and_write(plaintext, &recipient, &dest) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write secret: {e}")).into_response(),
    }
}
```

- [ ] **Step 2: Wire the route into `main.rs`**, behind the same `require_session` middleware as `/api/settings` (add it to the `protected` router built in Task 4 Step 2):

```rust
        .route("/api/secrets/:name", axum::routing::post(secrets_api::write_secret))
```

Add `mod secrets_api;` to `main.rs`'s module declarations.

- [ ] **Step 3: Real verification on ferrum-dev**

1. `cargo build -p ferrumd` — compiles.
2. Manual exercise against a real host with a real `ferrum.secrets."test-secret" = {};` entry in `settings.json`: `POST /api/secrets/test-secret` (with a session cookie) writes `/etc/ferrum/secrets/test-secret.sops`; confirm it's real, valid sops ciphertext by running `sops --decrypt --input-type binary --output-type binary /etc/ferrum/secrets/test-secret.sops` (with the box's own private key available) and getting back the exact plaintext posted.
3. `POST /api/secrets/not-declared-anywhere` (a name absent from `ferrum.secrets`) returns `400`, and confirm no file was written.

- [ ] **Step 4: Commit**

```bash
git add crates/ferrumd/src/secrets_api.rs crates/ferrumd/src/main.rs
git commit -m "Add the secrets API: write-only POST /api/secrets/:name, gated on ferrum.secrets"
```

---

## Task 6: Job API — the privilege-boundary integration, SSE progress, and the full daemon deployment

**Files:**
- Create: `crates/ferrumd/src/jobs.rs`
- Create: `crates/ferrumd/src/dbus.rs`
- Modify: `crates/ferrumd/Cargo.toml` (add `zbus`, `notify`, `uuid`)
- Modify: `crates/ferrumd/src/main.rs` (wire job routes, spawn the D-Bus signal listener)
- Modify: `crates/ferrum-apply/src/request.rs` — no change needed (already covers all five kinds); `ferrum-apply run-request`'s own dispatch (Task 2) already writes progress the SAME way `ferrum-apply apply` always has -- this task's own new requirement is that `run-request`'s `Apply`/`Rollback` arms ALSO write JSONL progress lines, which the existing `apply`/`rollback` modules don't currently do at all (they only print to stderr). **This is real new scope inside `crates/ferrum-apply`, not just `ferrumd`** -- see Step 1.
- Modify: `modules/core/daemon.nix` (add ferrumd's own systemd unit, now that the binary exists)
- Create: `nix/pkgs/ferrumd/default.nix`
- Modify: `nix/overlays/default.nix`, `nix/modules/flake/packages.nix`, `nix/modules/flake/checks.nix`
- Create: `tests/daemon-end-to-end.nix`

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: `POST /api/jobs`, `GET /api/jobs/:id/stream` (SSE) — the daemon's actual reason to exist.

- [ ] **Step 1: Add JSONL progress writing to `ferrum-apply`'s existing `apply`/`rollback` modules**

This is real, necessary scope this plan's earlier tasks under-specified: `crates/ferrum-apply/src/apply.rs`'s `run` function and `crates/ferrum-apply/src/rollback.rs`'s `run` function currently only ever print to stderr — nothing writes the JSONL progress file the design spec's "progress streams as JSONL" property depends on. Add a small, real progress-writer used by both:

In a new `crates/ferrum-apply/src/progress.rs`:

```rust
// A tiny, real JSONL progress writer -- one line per meaningful step,
// flushed immediately so a concurrently-tailing ferrumd sees each line
// as it's written, not batched. Only used when FERRUM_JOB_ID is set
// (i.e. this run was dispatched via `run-request`, not invoked by hand
// over SSH) -- a bare `ferrum-apply apply` run over SSH has no job id and
// no ferrumd tailing it, so it stays silent on this front exactly as it
// always has.
use std::io::Write;

pub struct Progress {
    file: Option<std::fs::File>,
}

impl Progress {
    pub fn open() -> Self {
        let job_id = std::env::var("FERRUM_JOB_ID").ok();
        let file = job_id.and_then(|id| {
            let dir = std::env::var("FERRUM_JOBS_DIR").unwrap_or_else(|_| "/var/lib/ferrum/jobs".to_string());
            std::fs::create_dir_all(&dir).ok()?;
            std::fs::OpenOptions::new().create(true).append(true).open(format!("{dir}/{id}.jsonl")).ok()
        });
        Self { file }
    }

    pub fn event(&mut self, event: &str, detail: &str) {
        if let Some(f) = &mut self.file {
            let line = serde_json::json!({
                "ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                "event": event,
                "detail": detail,
            });
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
    }

    pub fn complete(&mut self, result: &str, detail: &str) {
        self.event("complete", &format!("{result}: {detail}"));
    }
}
```

Add `Progress::open()` at the top of `apply::run` and `rollback::run`, and a `progress.event(...)` call after each of the numbered steps already described in their own doc comments (preflight, snapshot, switch, health-check for `apply`; validate/write-intent/switch-generation for `rollback`), plus `progress.complete(...)` at the very end with the real `ApplyResult` variant name. This is additive instrumentation — it must not change either function's actual control flow, return value, or existing stderr output.

- [ ] **Step 2: Write `crates/ferrumd/src/dbus.rs` — the real, spike-confirmed D-Bus client**

```rust
// Confirmed for real while writing this plan: this exact proxy definition
// compiles against zbus 4.x and successfully called the real systemd
// StartUnit method, receiving a real job object path back.
use zbus::{proxy, zvariant::OwnedObjectPath, Connection};

#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait SystemdManager {
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    #[zbus(signal)]
    fn job_removed(&self, id: u32, job: OwnedObjectPath, unit: String, result: String) -> zbus::Result<()>;
}

pub async fn start_ferrum_apply_unit(uuid: &str) -> anyhow::Result<()> {
    let connection = Connection::system().await?;
    let proxy = SystemdManagerProxy::new(&connection).await?;
    proxy
        .start_unit(&format!("ferrum-apply@{uuid}.service"), "replace")
        .await
        .map_err(|e| anyhow::anyhow!("failed to start ferrum-apply@{uuid}.service: {e}"))?;
    Ok(())
}
```

- [ ] **Step 3: Write `crates/ferrumd/src/jobs.rs` — request serialization, job tracking, SSE**

```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Json,
};
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

use crate::AppState;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobRequest {
    Preflight,
    Apply,
    Rollback { to: u32 },
    RestoreState,
    Gc,
}

fn jobs_dir() -> std::path::PathBuf {
    std::env::var("FERRUM_JOBS_DIR").unwrap_or_else(|_| "/var/lib/ferrum/jobs".to_string()).into()
}

fn requests_dir() -> std::path::PathBuf {
    std::env::var("FERRUM_REQUESTS_DIR").unwrap_or_else(|_| "/run/ferrum/requests".to_string()).into()
}

/// ferrumd itself serializes job requests -- apply/rollback are inherently
/// exclusive operations against the same generation sequence, so this is
/// a deliberate simplification rather than relying on systemd or
/// ferrum-apply to arbitrate concurrent runs.
pub async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(req): Json<JobRequest>,
) -> impl IntoResponse {
    {
        let running = state.job_running.lock().unwrap();
        if *running {
            return (StatusCode::CONFLICT, "a job is already running").into_response();
        }
    }

    let uuid = Uuid::new_v4().to_string();
    let body = match &req {
        JobRequest::Preflight => serde_json::json!({"kind": "preflight"}),
        JobRequest::Apply => serde_json::json!({"kind": "apply"}),
        JobRequest::Rollback { to } => serde_json::json!({"kind": "rollback", "to": to}),
        JobRequest::RestoreState => serde_json::json!({"kind": "restore_state"}),
        JobRequest::Gc => serde_json::json!({"kind": "gc"}),
    };

    let dir = requests_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to create requests dir: {e}")).into_response();
    }
    let request_path = dir.join(format!("{uuid}.json"));
    if let Err(e) = std::fs::write(&request_path, body.to_string()) {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write request file: {e}")).into_response();
    }

    if let Err(e) = crate::dbus::start_ferrum_apply_unit(&uuid).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    *state.job_running.lock().unwrap() = true;
    (StatusCode::OK, Json(serde_json::json!({"id": uuid}))).into_response()
}

/// Replays the job's own JSONL progress file from the start, then
/// switches to live-tail via polling (a simple, real, correct baseline --
/// inotify-based tailing via the `notify` crate is a real optimization
/// worth doing, but polling every 500ms is trivially correct and good
/// enough for a human watching one job's own progress; note this as a
/// deliberate simplification, not an oversight, if profiling later shows
/// it matters).
pub async fn stream_job(Path(id): Path<String>) -> impl IntoResponse {
    let path = jobs_dir().join(format!("{id}.jsonl"));
    let stream = async_stream::stream! {
        let mut last_len: u64 = 0;
        loop {
            let Ok(content) = std::fs::read_to_string(&path) else {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };
            let bytes = content.as_bytes();
            if (bytes.len() as u64) > last_len {
                for line in content[last_len as usize..].lines() {
                    if !line.trim().is_empty() {
                        yield Ok::<_, Infallible>(Event::default().event("progress").data(line.to_string()));
                    }
                }
                last_len = bytes.len() as u64;
            }
            if content.lines().last().map(|l| l.contains("\"complete\"")).unwrap_or(false) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}
```

Add `job_running: Mutex<bool>` to `AppState` (Task 3's `main.rs`), initialized `false`. Add `uuid = { version = "1", features = ["v4"] }` and `async-stream = "0.3"` to `crates/ferrumd/Cargo.toml`'s `[dependencies]`, alongside `zbus = { version = "4", default-features = false, features = ["tokio"] }` and `notify = "6"` (the `notify` crate isn't actually used by the polling-based `stream_job` above — do not add it unless a later real optimization needs it; keeping unused dependencies out is a real code-quality concern, not a nice-to-have).

- [ ] **Step 4: Spawn a background task clearing `job_running` on completion, wired into `main.rs`**

```rust
    // Independently confirms job completion via systemd's own JobRemoved
    // D-Bus signal, so `job_running` is cleared even if ferrum-apply
    // crashed before ever writing a "complete" line to its own progress
    // file -- see this plan's spec Known Risk #2 for why a job can
    // otherwise be left "running" forever.
    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Ok(connection) = zbus::Connection::system().await {
                if let Ok(proxy) = dbus::SystemdManagerProxy::new(&connection).await {
                    if let Ok(mut stream) = proxy.receive_job_removed().await {
                        use futures::StreamExt;
                        while let Some(_signal) = stream.next().await {
                            *state.job_running.lock().unwrap() = false;
                        }
                    }
                }
            }
        });
    }
```

Add `futures = "0.3"` to `Cargo.toml`.

- [ ] **Step 5: Wire the job routes into `main.rs`**, behind `require_session` (added to the `protected` router from Task 4):

```rust
        .route("/api/jobs", axum::routing::post(jobs::create_job))
        .route("/api/jobs/:id/stream", axum::routing::get(jobs::stream_job))
```

Add `mod jobs; mod dbus;` to `main.rs`'s module declarations.

- [ ] **Step 6: Complete `modules/core/daemon.nix` — add ferrumd's own systemd unit**

Append to the existing `modules/core/daemon.nix` (from Task 2), inside the same `lib.mkIf ferrum.daemon.enable { ... }` block:

```nix
  systemd.services.ferrumd = {
    description = "ferrumd -- the unprivileged ferrum web daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    environment = {
      FERRUMD_STATE_DIR = "/var/lib/ferrum";
      FERRUMD_LISTEN_ADDRESS = ferrum.daemon.listenAddress;
      FERRUMD_PORT = toString ferrum.daemon.port;
      FERRUM_SETTINGS_PATH = "/etc/ferrum/settings.json";
      FERRUM_SECRETS_DIR = ferrum.secretsDir;
      FERRUM_HOST_KEY_PUB = "/etc/ssh/ssh_host_ed25519_key.pub";
      FERRUM_JOBS_DIR = "/var/lib/ferrum/jobs";
      FERRUM_REQUESTS_DIR = "/run/ferrum/requests";
      FERRUM_SETTINGS_SCHEMA = "${pkgs.ferrum-settings-schema}/share/ferrum/settings-schema.json";
    };
    serviceConfig = {
      Type = "simple";
      User = "ferrum";
      Group = "ferrum";
      ExecStart = "${pkgs.ferrumd}/bin/ferrumd";
      ProtectSystem = "strict";
      ReadWritePaths = [ "/var/lib/ferrum" "/etc/ferrum/settings.json" "/etc/ferrum/secrets" "/run/ferrum" ];
      CapabilityBoundingSet = "";
      NoNewPrivileges = true;
      Restart = "on-failure";
    };
  };
```

- [ ] **Step 7: Package `ferrumd` for Nix**

`nix/pkgs/ferrumd/default.nix`:

```nix
{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "ferrumd";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrumd";
}
```

Add `ferrumd = final.callPackage ../pkgs/ferrumd { };` to `nix/overlays/default.nix` (alongside `ferrum-apply`/`ferrum-reconcile`/`ferrum-testapp` — this is the same missing-overlay-entry class of gap Phase 1.4c's Task 3 found for `ferrum-reconcile`; do not repeat it here). Add `ferrumd = pkgs.callPackage ../../../nix/pkgs/ferrumd { };` to `nix/modules/flake/packages.nix`. Add `cargo-test-ferrumd`/`clippy-ferrumd` entries to `nix/modules/flake/checks.nix`, mirroring the existing `ferrum-reconcile` pair exactly.

- [ ] **Step 8: Write `tests/daemon-end-to-end.nix` — the real proof this plan's core deliverable works**

```nix
{ pkgs }:
pkgs.testers.runNixOSTest {
  name = "daemon-end-to-end";
  nodes.machine = { config, lib, pkgs, ... }: {
    imports = [ (../modules/core/daemon.nix) ];
    options.ferrum = lib.mkOption { type = lib.types.raw; default = { }; };
    config = {
      ferrum.daemon = { enable = true; port = 7788; listenAddress = "127.0.0.1"; };
      ferrum.secretsDir = "/etc/ferrum/secrets";
      ferrum.secrets."test-secret" = { };
      environment.etc."ferrum/settings.json".text = builtins.toJSON {
        secrets."test-secret" = { };
      };
      systemd.tmpfiles.rules = [
        "Z /etc/ferrum/settings.json 0664 root ferrum - -"
        "d /etc/ferrum/secrets 0750 ferrum ferrum - -"
      ];
      services.openssh.enable = true;
      environment.systemPackages = [ pkgs.curl pkgs.sops ];
      system.stateVersion = "25.11";
    };
  };
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("ferrumd.service")
    machine.wait_for_open_port(7788)

    print("=== real login with the real bootstrap password ===")
    password = machine.succeed("cat /var/lib/ferrum/ferrumd-setup-password").strip()
    login_response = machine.succeed(
        f"curl -s -c /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/login "
        f"-H 'Content-Type: application/json' "
        f"-d '{{\\"username\\":\\"admin\\",\\"password\\":\\"{password}\\"}}'"
    )
    print(f"login response: {login_response}")
    assert "csrf_token" in login_response

    print("=== real settings write ===")
    machine.succeed(
        "curl -s -b /tmp/cookies.txt -X PUT http://127.0.0.1:7788/api/settings "
        "-H 'Content-Type: application/json' "
        "-d '{\\"secrets\\":{\\"test-secret\\":{}}}'"
    )
    settings_content = machine.succeed("cat /etc/ferrum/settings.json")
    assert "test-secret" in settings_content
    print("PASS: real settings write landed on disk")

    print("=== real secret write, confirmed by real decryption ===")
    machine.succeed(
        "curl -s -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/secrets/test-secret "
        "-d 'a-real-secret-value'"
    )
    decrypted = machine.succeed(
        "sops --decrypt --input-type binary --output-type binary /etc/ferrum/secrets/test-secret.sops"
    ).strip()
    assert decrypted == "a-real-secret-value", f"expected the real posted value, got: {decrypted}"
    print("PASS: real secret round-tripped through real sops encryption")

    print("=== real job trigger: preflight, through the real privilege boundary ===")
    job_response = machine.succeed(
        "curl -s -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\\"kind\\":\\"preflight\\"}'"
    )
    print(f"job response: {job_response}")
    import json
    job_id = json.loads(job_response)["id"]

    machine.wait_until_succeeds(
        f"grep -q complete /var/lib/ferrum/jobs/{job_id}.jsonl"
    )
    progress = machine.succeed(f"cat /var/lib/ferrum/jobs/{job_id}.jsonl")
    print(f"real progress log: {progress}")
    assert "complete" in progress
    print("PASS: a real job, triggered over the real HTTP API, ran through the real privilege boundary and produced a real progress log")

    print("=== second job while first believed running is correctly rejected, then succeeds once cleared ===")
    # (job_running should already be false again by this point since the
    # first job completed and the JobRemoved listener cleared it -- this
    # asserts that specifically, not a race.)
    second_job = machine.succeed(
        "curl -s -w '\\nHTTP_CODE:%{http_code}' -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\\"kind\\":\\"preflight\\"}'"
    )
    assert "HTTP_CODE:200" in second_job, f"expected the job-running flag to have cleared after the first job completed: {second_job}"
    print("PASS: job_running correctly cleared after completion, allowing a real second job")
  '';
}
```

Wire it into `nix/modules/flake/checks.nix`: `daemon-end-to-end = import ../../../tests/daemon-end-to-end.nix { inherit pkgs; };`.

- [ ] **Step 9: Real verification on ferrum-dev**

1. `cargo test --workspace --manifest-path crates/Cargo.toml` — every test across all four crates passes.
2. `cargo clippy --workspace --manifest-path crates/Cargo.toml --all-targets -- -D warnings` — clean (aside from the two pre-existing, already-documented `apply.rs` failures).
3. `nix build .#ferrumd` — succeeds.
4. `nix build .#checks.x86_64-linux.daemon-end-to-end --print-build-logs` — **the test that actually proves this plan's core deliverable**: real login, real settings write, real secret write with real decryption confirming the round-trip, and a real job triggered over HTTP that goes through the real polkit/D-Bus mechanism and produces a real progress log ending in `complete`. This is not optional polish — do not mark this task, or this plan, complete without this test genuinely passing.

- [ ] **Step 10: Commit**

```bash
git add crates/ferrum-apply/src/progress.rs crates/ferrum-apply/src/apply.rs crates/ferrum-apply/src/rollback.rs crates/ferrumd/src/jobs.rs crates/ferrumd/src/dbus.rs crates/ferrumd/Cargo.toml crates/ferrumd/src/main.rs modules/core/daemon.nix nix/pkgs/ferrumd nix/overlays/default.nix nix/modules/flake/packages.nix nix/modules/flake/checks.nix tests/daemon-end-to-end.nix
git commit -m "Add the job API: real D-Bus-triggered ferrum-apply runs, JSONL progress, SSE streaming, and the full daemon deployment"
```
