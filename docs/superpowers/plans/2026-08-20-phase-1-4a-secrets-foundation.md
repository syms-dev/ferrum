# Phase 1.4a — Secrets Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire sops-nix into ferrum, give `ferrum-apply` a new preflight step that auto-generates each servarr app's API key as a real sops secret, and migrate qBittorrent's WireGuard config out of `settings.json` into a proper operator-provided sops secret.

**Architecture:** sops-nix decrypts everything at system activation into `/run/secrets/` (tmpfs), using the box's own SSH host key as its age identity (no separate key-provisioning step). Two write paths populate the encrypted `.sops` files themselves: `ferrum-apply` auto-generates per-app API keys as a new pipeline step before every build (needed before Sonarr/Radarr/Prowlarr can even evaluate, since their `environmentFiles` reference the decrypted path statically); operator-provided secrets (qBittorrent's WireGuard config in this plan) are written by hand for now, with the zero-privilege `sops encrypt` mechanism this plan builds is the same one ferrumd will use in Phase 1.5.

**Tech Stack:** sops-nix (NixOS module + `sops`/`age`/`ssh-to-age` CLI tools), Rust (`ferrum-apply`).

**Spec:** [docs/superpowers/specs/2026-08-20-phase-1-4-proxy-secrets-reconciler-design.md](../specs/2026-08-20-phase-1-4-proxy-secrets-reconciler-design.md) — this plan implements that spec's Secrets section (and the qBittorrent WireGuard migration it calls out), plus enough of the Proxy section to add `ferrum.daemon.subdomain`. The proxy/auth/reconciler/Recyclarr work is a separate plan (Phase 1.4b) that depends on this one.

## Global Constraints

- Secret values never get Nix-string-interpolated into a systemd unit's script/environment/ExecStart text — this was already the hard rule for qBittorrent's WireGuard config in Phase 1.3; every secret this plan handles follows it.
- `sops.validateSopsFiles` (a real sops-nix option, defaults to `true`) checks every referenced `.sops` file exists **at Nix evaluation time** — confirmed empirically on ferrum-dev by reading sops-nix's own source (`sopsFileHash = ... builtins.hashFile "sha256" config.sopsFile`, gated on this option). The example host used by `checks.eval-example-hosts` is not a real deployed box and has no real secrets, so it sets this to `false` — matching the existing precedent of that host's fake dual-fstype filesystems, both there purely to satisfy eval-time checks a real box would never need faked.
- **`sopsFile` must be a genuine Nix `path` value, never a plain interpolated string, even though both look identical when printed.** Read directly from sops-nix's own assertion (`modules/sops/manifest-for.nix`): a secret fails validation unless `builtins.isPath secret.sopsFile` is true, OR it's a string already prefixed with `/nix/store`. `sopsFile = "${ferrum.secretsDir}/<name>.sops";` (plain string interpolation) satisfies neither — it evaluates fine and even passes `builtins.pathExists`, but fails this specific assertion the moment a real host actually validates (this is NOT the same eval-only host that has `validateSopsFiles = false`, so the cheap checks alone cannot catch it). The fix, confirmed via a real `nix eval` on ferrum-dev: `sopsFile = /. + "${ferrum.secretsDir}/<name>.sops";` — Nix's `path + string` concatenation operator produces a genuine path-typed value (`builtins.isPath` true) even when the string operand is a runtime-configurable value, which is what actually satisfies the assertion while keeping `ferrum.secretsDir` a plain configurable option. Every `sopsFile` assignment in this plan uses this form.
- Encrypting a NEW secret with `sops --encrypt --age <recipient>` needs only the recipient's **public** key — confirmed via `nix run nixpkgs#sops -- --help` on ferrum-dev. Nothing that writes a secret in this plan (ferrum-apply's new preflight step) needs the box's private key at all.
- The box's age identity is derived from its own SSH host key (`sops.age.sshKeyPaths`, which defaults to `config.services.openssh.hostKeys`'s ed25519 keys) — confirmed by reading sops-nix's source directly. This needs `services.openssh.enable = true`, which nothing in ferrum's module tree sets yet.
- Every option under `ferrum.*` must stay JSON-expressible — `checks.schema-uniformity` enforces this mechanically. New options this plan adds (`ferrum.secretsDir`, `ferrum.daemon.subdomain`) are plain strings, so this holds automatically.
- No per-app VM test files. Verification is real `nix build`/`nix eval` plus real service-start verification on [[reference-ferrum-dev-vm]], done by the controller after each task, matching every prior phase in this project.

---

## Task 1: Wire sops-nix into the flake, add core options

**Files:**
- Modify: `flake.nix`
- Modify: `modules/lib/default.nix`
- Modify: `nix/modules/flake/checks.nix`
- Modify: `modules/core/options.nix`
- Create: `modules/core/secrets.nix`
- Modify: `modules/default.nix` (add `./core/secrets.nix` to imports)

**Interfaces:**
- Consumes: `sops-nix` flake input (already declared in `flake.nix`, unused until now).
- Produces: `config.sops.secrets.<name>` (sops-nix's own option, now reachable from every ferrum module), `ferrum.secretsDir` (default `/etc/ferrum/secrets`), `ferrum.daemon.subdomain` (default `"ferrum"`) — later tasks in this plan and Phase 1.4b both consume `ferrum.secretsDir` to construct each secret's `sopsFile` path.

- [ ] **Step 1: Thread `sops-nix` into `ferrumLib.mkHost`**

Modify `modules/lib/default.nix`:

```nix
# ferrum.lib -- helpers exposed to host flakes.
#
# Deliberately thin: a host flake imports the ferrum module itself, passes
# its settings.json in as a plain attrset, and lets NixOS's own module
# system do the type-checking. See modules/default.nix for the module this
# wraps and docs/superpowers/specs/... for why settings are threaded in at
# the host-flake level rather than read from a path inside config.ferrum
# (reading a path out of config.ferrum in order to define config.ferrum is
# infinite recursion).
{ nixpkgs, sopsNix }:
let
  inherit (nixpkgs) lib;
  ferrumModule = import ../default.nix;
in
{
  # mkHost turns a settings attrset (typically `builtins.fromJSON
  # (builtins.readFile ./settings.json)`) plus any hand-written modules
  # (typically hardware-configuration.nix, disko.nix, and everything under
  # custom/) into a full nixosSystem.
  mkHost =
    { system
    , settings
    , modules ? [ ]
    , revision ? "unknown"
    , stateVersion ? "25.11"
    }:
    lib.nixosSystem {
      inherit system;
      specialArgs = { inherit revision; };
      modules = [
        sopsNix.nixosModules.sops
        ferrumModule
        { config.ferrum = settings; }
        { system.stateVersion = lib.mkDefault stateVersion; }
      ] ++ modules;
    };

  # importDir lists the *.nix files directly inside a directory, for wiring
  # up /etc/ferrum/custom -- the directory ferrumd is never given write
  # access to (see modules/core/daemon.nix once it exists).
  importDir = dir:
    let
      names = builtins.attrNames (builtins.readDir dir);
      nixFiles = builtins.filter (n: lib.hasSuffix ".nix" n) names;
    in
    map (n: dir + "/${n}") nixFiles;
}
```

- [ ] **Step 2: Pass `sops-nix` in from `flake.nix`**

Modify `flake.nix`'s `flake.lib` line:

```nix
      flake = {
        nixosModules.default = import ./modules;

        lib = import ./modules/lib { inherit nixpkgs; sopsNix = inputs.sops-nix; };
      };
```

- [ ] **Step 3: Update `nix/modules/flake/checks.nix`'s `ferrumLib` construction, disable sops file validation on the example host**

Modify the top of `nix/modules/flake/checks.nix`:

```nix
{ inputs, ... }:
{
  perSystem = { system, pkgs, lib, self', ... }:
    let
      ferrumLib = import ../../../modules/lib {
        nixpkgs = inputs.nixpkgs;
        sopsNix = inputs.sops-nix;
      };
      catalog = import ../../../modules/lib/catalog.nix { inherit lib; };
      appsDir = ../../../modules/apps;

      exampleHosts = {
        minimal = ferrumLib.mkHost {
          inherit system;
          settings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
          modules = [
            ../../../examples/hosts/minimal/configuration.nix
            # This host is eval-only (see configuration.nix's own "NOT
            # BOOTABLE" comment) and never has real secrets on disk.
            # sops.validateSopsFiles defaults to true and requires every
            # referenced .sops file to physically exist at eval time
            # (confirmed by reading sops-nix's own source: it computes
            # builtins.hashFile on each one) -- a real deployed box has
            # these because ferrum-apply generates them before every
            # build, but nothing does that for this check.
            { sops.validateSopsFiles = false; }
          ];
          revision = "ci";
        };
      };
```

(The rest of the file is unchanged — leave every line after this block exactly as it was.)

- [ ] **Step 4: Add `ferrum.secretsDir` and `ferrum.daemon.subdomain` options**

Modify `modules/core/options.nix` — add `secretsDir` as a new top-level entry under `options.ferrum` (next to `storage`), and add `subdomain` to the existing `daemon` block:

```nix
    secretsDir = mkOption {
      type = types.str;
      default = "/etc/ferrum/secrets";
      description = ''
        Where per-secret .sops files live on a real deployed box (this is
        NOT the decrypted output -- that's sops-nix's own /run/secrets/,
        entirely outside ferrum's control). /etc/ferrum is the host's own
        flake root (see the Phase 1.3 design doc), so paths under here get
        copied into the Nix store at eval time same as settings.json --
        that's fine, since only ciphertext ever lives here.
      '';
    };
```

Add this block right after the closing `};` of the `storage = { ... };` block (i.e. as a sibling of `storage`, `proxy`, `auth`, `secrets`, `backup`, `apply`, `daemon`, `apps`).

Then modify the existing `daemon = { ... };` block to add one more option:

```nix
    daemon = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether ferrumd (the web UI) runs on this host.";
      };
      port = mkOption {
        type = types.port;
        default = 7788;
      };
      listenAddress = mkOption {
        type = types.str;
        default = "127.0.0.1";
      };
      subdomain = mkOption {
        type = types.str;
        default = "ferrum";
        description = "Hostname label under ferrum.proxy.baseDomain for the daemon's own web UI -- same mechanism as every app's own subdomain option, just not tied to the catalog since the daemon isn't a catalog app.";
      };
    };
```

- [ ] **Step 5: Create `modules/core/secrets.nix`**

```nix
# Wires sops-nix's decrypt side (config.sops.*) into every ferrum host.
# The box's age identity is derived from its own SSH host key -- no
# separate key-provisioning step, no key to lose track of during
# nixos-anywhere install: sops.age.sshKeyPaths already defaults to
# config.services.openssh.hostKeys's ed25519 keys (confirmed by reading
# sops-nix's own source), so all this module needs to do is make sure
# openssh is actually enabled, since sops-nix's own assertion requires
# either that, an explicit sops.age.keyFile, or GPG -- and nothing in
# ferrum's module tree turns on openssh otherwise.
#
# The ENCRYPT side (turning a plaintext value into a new .sops file) is
# deliberately NOT here -- it needs only the box's PUBLIC age key
# (ssh-to-age on the host's own ssh_host_ed25519_key.pub), needs no
# privilege at all, and is implemented independently by whatever writes a
# given secret: modules/apps/*/service.nix's own commit for the
# auto-generated per-app API keys, or a later ferrumd change for
# operator-provided secrets (see the design spec). This module is decrypt
# plumbing only.
{ lib, ... }:
{
  services.openssh.enable = lib.mkDefault true;
}
```

- [ ] **Step 6: Import `secrets.nix` in `modules/default.nix`**

Add `./core/secrets.nix` to the existing `imports` list (alongside `./core/options.nix`, `./core/storage.nix`, etc. — same position/style as the other `./core/*` entries).

- [ ] **Step 7: Verify structural checks pass**

On [[reference-ferrum-dev-vm]]: sync the worktree, run
```bash
nix build .#checks.x86_64-linux.catalog-consistency .#checks.x86_64-linux.schema-uniformity .#checks.x86_64-linux.eval-example-hosts --no-link
```
All three must pass. This is the check that proves `validateSopsFiles = false` on the example host actually avoided the eval-time file-existence requirement — if this task is wrong about that, `eval-example-hosts` fails here, not later.

- [ ] **Step 8: Commit**

```bash
git add flake.nix modules/lib/default.nix nix/modules/flake/checks.nix modules/core/options.nix modules/core/secrets.nix modules/default.nix
git commit -m "Wire sops-nix into ferrum; add ferrum.secretsDir and ferrum.daemon.subdomain"
```

---

## Task 2: `ferrum-apply`'s secret-generation preflight step

**Files:**
- Create: `crates/ferrum-apply/src/secrets.rs`
- Modify: `crates/ferrum-apply/src/main.rs` (add `mod secrets;`, wire env vars)
- Modify: `crates/ferrum-apply/src/apply.rs` (call `secrets::ensure_all` as a new first step)
- Modify: `nix/pkgs/ferrum-apply/default.nix` (wrap with `sops`/`ssh-to-age` on PATH, same pattern as the existing `btrfs-progs` wrap)
- Modify: `modules/core/overlays.nix` (extend the existing `ferrum-apply` `--set-default` wrapper with the two new env vars — see Step 6)

**Interfaces:**
- Consumes: `crate::apply::run`'s existing pipeline shape (Task 1 confirmed `1. Build → 2. Preflight → 3. Stop apps → ...`); this task inserts a **new step 0, before Build**, since Sonarr/Radarr/Prowlarr's `environmentFiles` reference a decrypted secret path statically, and `nix build` needs the `.sops` file to exist on disk for `sops.validateSopsFiles` (real, on by default) to pass.
- Produces: `secrets::ensure_all(secrets_dir: &Path, recipient: &str, apps: &[&str]) -> anyhow::Result<()>` — called once per apply, idempotent (skips any app whose `.sops` file already exists). `secrets::host_age_recipient() -> anyhow::Result<String>` — derives the box's public age recipient from its own SSH host key via `ssh-to-age`, for later tasks (and Phase 1.4b) to reuse rather than reimplementing.

- [ ] **Step 1: Write `crates/ferrum-apply/src/secrets.rs`**

```rust
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
```

- [ ] **Step 2: Wire `secrets::ensure_all` as Step 0 in `apply.rs`'s pipeline**

Modify `crates/ferrum-apply/src/apply.rs`'s `pub fn run` — add a new `StorageConfig` field and a call before the existing Step 1 (Build):

Find the `pub struct StorageConfig` definition (near the top of `apply.rs`, referenced from `main.rs`) and add two fields:

```rust
    pub secrets_dir: PathBuf,
    pub servarr_apps: Vec<String>,
```

Then at the very top of `pub fn run(flake_ref: &str, storage: &StorageConfig) -> anyhow::Result<ApplyResult> {`, before the existing `// 1. Build` comment, insert:

```rust
    // 0. Ensure every enabled servarr app has its API-key secret, BEFORE
    // build -- their environmentFiles reference the decrypted path
    // statically, and sops.validateSopsFiles (on by default) checks the
    // .sops file exists at Nix EVAL time, which happens inside the build
    // step right after this.
    let recipient = crate::secrets::host_age_recipient()?;
    let servarr_refs: Vec<&str> = storage.servarr_apps.iter().map(String::as_str).collect();
    crate::secrets::ensure_all(&storage.secrets_dir, &recipient, &servarr_refs)?;

```

- [ ] **Step 3: Wire the new fields through `main.rs`**

Add `mod secrets;` to the `mod` list at the top of `main.rs`. In the `Command::Apply` match arm, add to the `StorageConfig { ... }` construction:

```rust
                secrets_dir: std::env::var("FERRUM_SECRETS_DIR")
                    .unwrap_or_else(|_| "/etc/ferrum/secrets".to_string())
                    .into(),
                servarr_apps: std::env::var("FERRUM_SERVARR_APPS")
                    .unwrap_or_else(|_| "sonarr,radarr,prowlarr".to_string())
                    .split(',')
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
                    .collect(),
```

(`FERRUM_SERVARR_APPS` is env-driven rather than hardcoded so a host that hasn't enabled all three doesn't waste a `ssh-to-age`+`sops` round trip per app that's off — Phase 1.4b's NixOS module wiring sets this from the actual enabled-apps list, matching the `FERRUM_*` env-var convention every other `ferrum-apply` config value already uses.)

- [ ] **Step 4: Add `rand`-free hex encoding note and update `Cargo.toml` if needed**

No new crate dependencies are needed — `secrets.rs` uses only `std::fs`, `std::process`, and the crate's existing `anyhow`. Confirm `crates/ferrum-apply/Cargo.toml` is unchanged.

- [ ] **Step 5: Update the Nix package wrapper**

Modify `nix/pkgs/ferrum-apply/default.nix`:

```nix
{ rustPlatform, lib, makeWrapper, btrfs-progs, sops, ssh-to-age }:
rustPlatform.buildRustPackage {
  pname = "ferrum-apply";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-apply";

  # ferrum-apply shells out to `btrfs` (preflight's check_is_subvolume, and
  # later apply/restore-state's snapshot/swap commands), plus `sops` and
  # `ssh-to-age` (secrets::ensure_all's encrypt-only secret generation).
  # nativeCheckInputs alone only puts these on PATH during this
  # derivation's own checkPhase -- it does NOT reach the installed binary
  # at runtime, so it's paired here with a wrapper that guarantees they're
  # all on PATH wherever this binary actually runs, independent of whether
  # a consuming systemd unit remembers to supply them too.
  nativeCheckInputs = [ btrfs-progs sops ssh-to-age ];
  nativeBuildInputs = [ makeWrapper ];
  postFixup = ''
    wrapProgram $out/bin/ferrum-apply --prefix PATH : ${lib.makeBinPath [ btrfs-progs sops ssh-to-age ]}
  '';
}
```

- [ ] **Step 6: Wire the two new env vars into the existing `ferrum-apply` wrapper**

`modules/core/overlays.nix` already wraps the base `ferrum-apply` package with `--set-default FERRUM_STATE_DIR ...` etc., baking `ferrum.storage.*`/`ferrum.apply.*` into the CLI so it can never silently disagree with the host's own config (see that file's header comment — this is the established mechanism, not something to reinvent). This step extends that same wrapper with the two new env vars Step 3 added: `FERRUM_SECRETS_DIR` (from `ferrum.secretsDir`) and `FERRUM_SERVARR_APPS` (the actual enabled servarr apps on this host, not a hardcoded list — a host that hasn't enabled Prowlarr shouldn't have `ferrum-apply` waste a `ssh-to-age`+`sops` round trip generating a secret nothing uses, and a host that HAS enabled all three needs all three represented).

Modify `modules/core/overlays.nix`'s `nixpkgs.overlays` list — add one `let`-bound value and two more `--set-default` lines to the existing `ferrum-apply` wrapper derivation:

```nix
  ferrum = config.ferrum;

  # ...(unchanged: catalog, unfreePackageNames)...

  # Only the three servarr apps ferrum-apply's secrets.rs module actually
  # generates keys for (see crates/ferrum-apply/src/secrets.rs's own
  # SERVARR_APPS list) -- qBittorrent/Plex/Jellyfin/SABnzbd have their own
  # auth mechanisms and are deliberately excluded even if enabled.
  enabledServarrApps = lib.filter
    (id: ferrum.apps.${id}.enable or false)
    [ "sonarr" "radarr" "prowlarr" ];
```

(Add `enabledServarrApps` as a new `let`-binding alongside the existing `ferrum`/`catalog`/`unfreePackageNames` bindings, before the `in` keyword.)

Then add two more `--set-default` lines to the existing `makeWrapper` invocation:

```nix
          makeWrapper ${prev.ferrum-apply}/bin/ferrum-apply $out/bin/ferrum-apply \
            --set-default FERRUM_STATE_DIR ${lib.escapeShellArg ferrum.storage.stateDir} \
            --set-default FERRUM_SNAPSHOT_DIR ${lib.escapeShellArg ferrum.storage.snapshotDir} \
            --set-default FERRUM_JOURNAL_DIR ${lib.escapeShellArg ferrum.storage.journalDir} \
            --set-default FERRUM_MIN_FREE_GIB ${toString ferrum.storage.minFreeGiB} \
            --set-default FERRUM_HEALTH_CHECK_TIMEOUT_SEC ${toString ferrum.apply.healthCheckTimeoutSec} \
            --set-default FERRUM_SECRETS_DIR ${lib.escapeShellArg ferrum.secretsDir} \
            --set-default FERRUM_SERVARR_APPS ${lib.escapeShellArg (lib.concatStringsSep "," enabledServarrApps)}
```

(Every existing line keeps its trailing `\`; only the final line's `\` moves to the new last line, and the two new lines are added — this is one wrapper invocation, not two.)

- [ ] **Step 7: Run cargo tests**

```bash
cd crates && cargo test -p ferrum-apply
```
Expected: all tests pass, including the two new `secrets.rs` tests.

- [ ] **Step 8: Verify structural checks pass on ferrum-dev**

```bash
nix build .#checks.x86_64-linux.catalog-consistency .#checks.x86_64-linux.schema-uniformity .#checks.x86_64-linux.eval-example-hosts --no-link
cd crates && cargo test -p ferrum-apply && cargo clippy -p ferrum-apply -- -D warnings
```

- [ ] **Step 9: Commit**

```bash
git add crates/ferrum-apply/src/secrets.rs crates/ferrum-apply/src/main.rs crates/ferrum-apply/src/apply.rs nix/pkgs/ferrum-apply/default.nix modules/core/overlays.nix
git commit -m "Add ferrum-apply's secret-generation preflight step for servarr apps"
```

---

## Task 3: Wire Sonarr/Radarr/Prowlarr to their generated API keys

**Files:**
- Modify: `modules/apps/sonarr/service.nix`
- Modify: `modules/apps/radarr/service.nix`
- Modify: `modules/apps/prowlarr/service.nix`

**Interfaces:**
- Consumes: `ferrum.secretsDir` (Task 1), the `<app>-apikey.sops` files Task 2's `ferrum-apply` preflight step generates, `config.sops.secrets` (sops-nix's own option, now reachable via Task 1's flake wiring).
- Produces: nothing further tasks depend on — this is a terminal, independently-verifiable change per app.

- [ ] **Step 1: Wire Sonarr**

Modify `modules/apps/sonarr/service.nix` — replace the file's header comment (which currently says secret wiring is deferred to Phase 1.4) and add the `sops.secrets`/`environmentFiles` wiring:

```nix
# Sonarr, wired through the uniform ferrum.apps.sonarr submodule onto
# nixpkgs' services.sonarr (part of the shared servarr framework -- see
# nixos/modules/services/misc/servarr/ upstream).
#
# services.sonarr.environmentFiles points at sops-nix's decrypted API-key
# secret, generated by ferrum-apply's preflight step (see
# crates/ferrum-apply/src/secrets.rs) before every build -- Sonarr never
# generates its own key, ferrum chooses it up front, which is what makes
# the reconciler's cross-app registration (Phase 1.4b) possible without
# scraping config.xml.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.sonarr or { enable = false; };
in
lib.mkIf app.enable {
  sops.secrets."sonarr-apikey" = {
    sopsFile = /. + "${ferrum.secretsDir}/sonarr-apikey.sops";
    format = "binary";
    owner = "sonarr";
  };

  services.sonarr = {
    enable = true;
    dataDir = app.stateDir;
    user = "sonarr";
    group = "sonarr";
    openFirewall = false;
    environmentFiles = [ config.sops.secrets."sonarr-apikey".path ];
    settings = {
      server = {
        port = app.port;
        bindaddress = "127.0.0.1";
      } // lib.optionalAttrs (app.settings ? urlBase && app.settings.urlBase != "") {
        urlbase = app.settings.urlBase;
      };
      log.analyticsenabled = false;
      update.mechanism = "external";
    };
  };

  users.users.sonarr.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.sonarr = {
    # Pulled in by ferrum-apps.target instead of multi-user.target directly,
    # so `systemctl stop ferrum-apps.target` (what apply does before every
    # snapshot) actually controls it.
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    # Every app service must carry this condition itself, not just the
    # target -- verified against real systemd (tests/state-restore-interlock.nix):
    # WantedBy=/Wants= start-propagation from a target does NOT check the
    # target's own ConditionPathExists result, so putting the condition only
    # on ferrum-apps.target lets this unit start anyway when the target is
    # skipped. See modules/core/generations.nix for the full explanation.
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 2: Wire Radarr**

Replace the full contents of `modules/apps/radarr/service.nix`:

```nix
# Radarr, wired through the uniform ferrum.apps.radarr submodule onto
# nixpkgs' services.radarr (shares Sonarr's servarr framework -- see
# nixos/modules/services/misc/servarr/). environmentFiles points at
# sops-nix's decrypted API-key secret, generated by ferrum-apply's
# preflight step (see crates/ferrum-apply/src/secrets.rs) before every
# build -- same mechanism as Sonarr's, see that file's comment for why.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.radarr or { enable = false; };
in
lib.mkIf app.enable {
  sops.secrets."radarr-apikey" = {
    sopsFile = /. + "${ferrum.secretsDir}/radarr-apikey.sops";
    format = "binary";
    owner = "radarr";
  };

  services.radarr = {
    enable = true;
    dataDir = app.stateDir;
    user = "radarr";
    group = "radarr";
    environmentFiles = [ config.sops.secrets."radarr-apikey".path ];
    settings = {
      server = {
        port = app.port;
        bindaddress = "127.0.0.1";
      } // lib.optionalAttrs (app.settings ? urlBase && app.settings.urlBase != "") {
        urlbase = app.settings.urlBase;
      };
      log.analyticsenabled = false;
      update.mechanism = "external";
    };
  };

  users.users.radarr.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.radarr = {
    # Pulled in by ferrum-apps.target instead of multi-user.target directly,
    # so `systemctl stop ferrum-apps.target` (what apply does before every
    # snapshot) actually controls it, and the fail-closed interlock (every
    # app service must carry ConditionPathExists itself -- see
    # modules/core/generations.nix for why the target's own condition alone
    # doesn't gate dependents) applies.
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 3: Wire Prowlarr**

Replace the full contents of `modules/apps/prowlarr/service.nix`:

```nix
# Prowlarr, wired through the uniform ferrum.apps.prowlarr submodule onto
# nixpkgs' services.prowlarr. Unlike Sonarr/Radarr, the upstream module
# uses DynamicUser -- there is no persistent "prowlarr" user, so (correctly,
# since mediaAccess defaults to "none" for this app) there is no media-group
# wiring here, and the sops secret's `owner` is left at sops-nix's own
# default (root) rather than "prowlarr" -- systemd reads EnvironmentFile=
# as root before the service's dynamic user is even created, so there is
# no "prowlarr" user for the secret file to be owned by at the point it's
# read. environmentFiles points at sops-nix's decrypted API-key secret,
# generated by ferrum-apply's preflight step (see
# crates/ferrum-apply/src/secrets.rs) before every build -- same mechanism
# as Sonarr's, see that file's comment for why.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.prowlarr or { enable = false; };
in
lib.mkIf app.enable {
  sops.secrets."prowlarr-apikey" = {
    sopsFile = /. + "${ferrum.secretsDir}/prowlarr-apikey.sops";
    format = "binary";
  };

  services.prowlarr = {
    enable = true;
    dataDir = app.stateDir;
    environmentFiles = [ config.sops.secrets."prowlarr-apikey".path ];
    settings = {
      server = {
        port = app.port;
        bindaddress = "127.0.0.1";
      };
      log.analyticsenabled = false;
      update.mechanism = "external";
    };
  };

  systemd.services.prowlarr = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 4: Real verification on ferrum-dev**

This is the first task where the secret actually needs to exist and be consumed for real, so verification has one more real step than usual: build the example host's toplevel, activate it in a throwaway `pkgs.testers.runNixOSTest` (or `nixos-rebuild build-vm`-equivalent), and confirm:
1. `ferrum-apply`'s preflight step (invoked directly, not via a full generation switch — call `ferrum-apply apply` against a throwaway flake ref, or exercise `secrets::ensure_all` directly) produces real `.sops` files under the test's `FERRUM_SECRETS_DIR`.
2. `systemctl cat sonarr` (and radarr, prowlarr) on the booted test VM shows `EnvironmentFile=/run/secrets/sonarr-apikey` (sops-nix's real decrypted path) in the unit.
3. `cat /run/secrets/sonarr-apikey` on the booted VM shows the real `SONARR__AUTH__APIKEY=<32-hex-chars>` line — confirming the full round trip (generate → encrypt → decrypt → environment file) actually works, not just that the Nix wiring evaluates.
4. Confirm the secret's ciphertext, not plaintext, is what landed in the built closure: grep the built toplevel's store closure for the literal generated key value — it must not appear (same discipline as Phase 1.3's qBittorrent canary-secret check).

- [ ] **Step 5: Commit**

```bash
git add modules/apps/sonarr/service.nix modules/apps/radarr/service.nix modules/apps/prowlarr/service.nix
git commit -m "Wire Sonarr, Radarr, and Prowlarr to their ferrum-apply-generated API keys"
```

---

## Task 4: Migrate qBittorrent's WireGuard config to a real sops secret

**Files:**
- Modify: `modules/apps/qbittorrent/meta.nix`
- Modify: `modules/apps/qbittorrent/service.nix`
- Modify: `examples/hosts/minimal/settings.json` (remove the now-gone `vpnWireguardConfig` settings key if present; it defaults to `""` so likely absent already, but check)

**Interfaces:**
- Consumes: `ferrum.secretsDir` (Task 1), the existing `ferrum.secrets` option (operator-declared secret names — this was already in `modules/core/options.nix` from the original scaffold).
- Produces: closes the tech debt flagged in Phase 1.3's spec (`vpnWireguardConfig` no longer sits in plaintext in `settings.json`, and no longer needs the runtime-`jq`-read-from-settings.json trick — it now reads directly from sops-nix's own decrypted path, which is simpler AND closes the store-exposure gap Phase 1.3's final review found, since `/run/secrets/` is tmpfs and never part of any flake evaluation the way `/etc/ferrum/settings.json` is).

- [ ] **Step 1: Remove `vpnWireguardConfig` from qBittorrent's `settingsSchema`**

Modify `modules/apps/qbittorrent/meta.nix` — the `settingsSchema.properties` block currently has both `vpnWireguardConfig` and `vpnKillSwitch`. Remove `vpnWireguardConfig` entirely (it's no longer an `app.settings` key — the VPN config now lives in `ferrum.secrets`, addressed by a fixed name, not a per-app settings value); `vpnKillSwitch` stays exactly as-is (it's a plain boolean, never a secret):

```nix
  # vpnKillSwitch: see docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-
  # design.md's "qBittorrent VPN Kill Switch" section. The WireGuard config
  # itself moved to a real sops secret (ferrum.secrets."qbittorrent-vpn") in
  # Phase 1.4a -- see modules/apps/qbittorrent/service.nix. Nothing in
  # app.settings ever holds the config text anymore.
  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = {
      vpnKillSwitch = {
        type = "boolean";
        default = true;
      };
    };
  };
```

- [ ] **Step 2: Rewrite the VPN detection and config-reading logic in `service.nix`**

Modify `modules/apps/qbittorrent/service.nix`. `vpnEnabled` changes from checking a non-empty `app.settings` string to checking whether the operator has declared the `"qbittorrent-vpn"` secret at all (`ferrum.secrets ? "qbittorrent-vpn"`), and the netns-setup script's `jq`-read-from-`settings.json` step is replaced with a direct copy from sops-nix's own decrypted path (no `jq` needed at all now — sops-nix already did the decryption, ferrum-apply doesn't need to reach into `settings.json` for this anymore):

```nix
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.qbittorrent or { enable = false; };
  vpnEnabled = ferrum.secrets ? "qbittorrent-vpn";
  killSwitch = app.settings.vpnKillSwitch or true;
in
lib.mkIf app.enable {
  services.qbittorrent = {
    enable = true;
    profileDir = app.stateDir;
    user = "qbittorrent";
    group = "qbittorrent";
    webuiPort = app.port;
  };

  users.users.qbittorrent.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  sops.secrets."qbittorrent-vpn" = lib.mkIf vpnEnabled {
    sopsFile = /. + "${ferrum.secretsDir}/qbittorrent-vpn.sops";
    format = "binary";
  };

  # The WireGuard config is a real sops secret now (ferrum.secrets."qbittorrent-vpn"),
  # written by an operator through the same zero-privilege `sops encrypt`
  # mechanism ferrum-apply's own secret generation uses (see
  # crates/ferrum-apply/src/secrets.rs) -- never Nix-interpolated into this
  # unit, same hard rule as Phase 1.3. sops-nix already decrypted it to
  # /run/secrets/qbittorrent-vpn by the time this script runs, so there's
  # no jq/settings.json read needed anymore -- just copy the already-plaintext
  # file into the netns's own runtime directory.
  systemd.services.qbt-vpn-netns-setup = lib.mkIf vpnEnabled {
    description = "Create the VPN-gated network namespace for qBittorrent";
    unitConfig.DefaultDependencies = false;
    after = [ "network-pre.target" ];
    wants = [ "network-pre.target" ];
    before = [ "qbittorrent.service" ];
    path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.iptables pkgs.gawk pkgs.gnugrep pkgs.coreutils ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -euo pipefail
      ip netns del qbt-vpn 2>/dev/null || true
      ip netns add qbt-vpn
      mkdir -p -m 0700 /run/qbt-vpn
      umask 077
      cp ${config.sops.secrets."qbittorrent-vpn".path} /run/qbt-vpn/wg0.conf
      chmod 0600 /run/qbt-vpn/wg0.conf

      # Create the WireGuard interface in THIS (root) namespace first, then
      # move it into qbt-vpn -- a WireGuard interface's encrypted UDP
      # socket stays bound to whichever namespace it was created in, even
      # after the interface itself is moved elsewhere. Creating it
      # directly inside qbt-vpn leaves the encrypted tunnel traffic with no
      # route out (found for real during Phase 1.3's final whole-branch
      # review, confirmed via an actual WireGuard handshake test).
      wg_address=$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }' /run/qbt-vpn/wg0.conf)
      if [ -z "$wg_address" ]; then
        echo "qbt-vpn-netns-setup: no Address= line in the WireGuard config" >&2
        exit 1
      fi

      ip link del wg0 2>/dev/null || true
      ip link add wg0 type wireguard
      wg setconf wg0 <(wg-quick strip /run/qbt-vpn/wg0.conf)
      ip link set wg0 netns qbt-vpn
      ip netns exec qbt-vpn ip link set lo up
      ip netns exec qbt-vpn ip address add "$wg_address" dev wg0
      ip netns exec qbt-vpn ip link set wg0 up
      ip netns exec qbt-vpn ip route add default dev wg0

      mkdir -p /etc/netns/qbt-vpn
      wg_dns=$(awk -F'=' '/^[[:space:]]*DNS[[:space:]]*=/ { gsub(/[ \t]/, "", $2); print $2; exit }' /run/qbt-vpn/wg0.conf)
      : > /etc/netns/qbt-vpn/resolv.conf
      if [ -n "$wg_dns" ]; then
        IFS=',' read -ra dns_servers <<< "$wg_dns"
        for server in "''${dns_servers[@]}"; do
          echo "nameserver $server" >> /etc/netns/qbt-vpn/resolv.conf
        done
      fi

      ip link add veth-qbt-host type veth peer name veth-qbt-ns
      ip link set veth-qbt-ns netns qbt-vpn
      ip addr add 10.200.1.1/30 dev veth-qbt-host
      ip link set veth-qbt-host up
      ip netns exec qbt-vpn ip addr add 10.200.1.2/30 dev veth-qbt-ns
      ip netns exec qbt-vpn ip link set veth-qbt-ns up

      ${lib.optionalString (!killSwitch) ''
        echo 1 > /proc/sys/net/ipv4/ip_forward
        ip netns exec qbt-vpn ip route add default via 10.200.1.1 dev veth-qbt-ns metric 200
        iptables -t nat -A POSTROUTING -s 10.200.1.0/30 -j MASQUERADE
      ''}
    '';
    preStop = ''
      ip netns del qbt-vpn 2>/dev/null || true
      ip link del veth-qbt-host 2>/dev/null || true
      rm -rf /etc/netns/qbt-vpn
      ${lib.optionalString (!killSwitch) ''
        iptables -t nat -D POSTROUTING -s 10.200.1.0/30 -j MASQUERADE 2>/dev/null || true
      ''}
    '';
  };

  systemd.services.qbittorrent = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    after = lib.mkIf vpnEnabled [ "qbt-vpn-netns-setup.service" ];
    bindsTo = lib.mkIf vpnEnabled [ "qbt-vpn-netns-setup.service" ];
    serviceConfig = (lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    }) // lib.optionalAttrs vpnEnabled {
      NetworkNamespacePath = "/var/run/netns/qbt-vpn";
      BindReadOnlyPaths = [ "/etc/netns/qbt-vpn/resolv.conf:/etc/resolv.conf" ];
    };
  };
}
```

- [ ] **Step 3: Check `examples/hosts/minimal/settings.json` for a stale `vpnWireguardConfig` key**

Read the file; if qBittorrent's settings block has a `"vpnWireguardConfig"` key (even `""`), remove it — `additionalProperties = false` on the new `settingsSchema` means any leftover key here would fail `checks.schema-uniformity`. If the key isn't present (likely, since Phase 1.3 never set it in the example host), no change needed.

- [ ] **Step 4: Real verification on ferrum-dev**

Same class of real verification Phase 1.3's final review established for this exact mechanism — don't skip straight to trusting the diff:
1. `catalog-consistency`/`schema-uniformity`/`eval-example-hosts` all pass with `ferrum.secrets` left empty (the no-op path: `vpnEnabled` false, no netns unit created at all, `system.build.toplevel.drvPath` should be unaffected by qBittorrent's presence the same way Task 6/7 of Phase 1.3 confirmed).
2. With a real `ferrum.secrets."qbittorrent-vpn"` declared and a real encrypted secret placed at the configured `sopsFile` path (generate one with `sops --encrypt --age <test-recipient>`, a real WireGuard config with a real `wg genkey`-generated keypair, matching Phase 1.3's own verification methodology, including the real-handshake-against-a-local-test-peer test — reuse that exact technique, don't regress to a fake-peer test): confirm the netns comes up, confirm a genuine WireGuard handshake completes (not just that the interface exists), confirm the secret's plaintext never lands in the built store closure (grep the closure for the test config's literal content, same canary-string technique as Phase 1.3).

- [ ] **Step 5: Commit**

```bash
git add modules/apps/qbittorrent/meta.nix modules/apps/qbittorrent/service.nix
git commit -m "Migrate qBittorrent's WireGuard config from settings.json to a real sops secret"
```
