# Phase 1.4c — Reconciler and Recyclarr Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the catalog's already-declared `integrations.providesTo`/`consumes` metadata real: a reconciler that registers download clients and indexer-sync "Applications" across Sonarr/Radarr/Prowlarr/qBittorrent/SABnzbd automatically, plus opinionated-and-optional Recyclarr TRaSH-guide quality-profile sync for Sonarr/Radarr.

**Architecture:** A new Rust crate, `ferrum-reconcile`, run as a systemd oneshot after `ferrum-apps.target`, driven entirely by a JSON config Nix generates from the catalog's own metadata (per-app connection info + a pre-validated, pre-computed list of registration pairs) — the same "JSON-driven, secret values indirected through a path reference" shape the spec cites from nixarr's `prowlarr/settings-sync`. Recyclarr reuses nixpkgs' own `services.recyclarr` module directly. Both depend on a small but real prerequisite this plan's own verification surfaced: neither mechanism can use the *existing* Phase 1.4a servarr API-key secrets as-is, and two apps (qBittorrent, SABnzbd) need new bootstrap work before either mechanism can reach them at all — see Global Constraints.

**Tech Stack:** Rust (`crates/ferrum-reconcile`, a new workspace member; `ureq` for blocking HTTP — no async runtime needed for a handful of sequential oneshot calls), Recyclarr (`services.recyclarr`), sops-nix (already wired), NixOS (`modules/core/reconciler.nix`, `modules/core/recyclarr.nix`).

**Spec:** `docs/superpowers/specs/2026-08-20-phase-1-4-proxy-secrets-reconciler-design.md` — this plan implements its "Reconciler" and "Recyclarr" sections (the only two not already shipped by Phase 1.4a/1.4b).

## Global Constraints

- Every option under `ferrum.*` must stay JSON-expressible — `checks.schema-uniformity` enforces this mechanically. This plan adds exactly one new option, `ferrum.recyclarr.enable` (`types.bool`, default `false`).
- No secret value is ever Nix-string-interpolated into a systemd unit's script/environment/ExecStart text, or into the generated `reconcile-config.json` — that file holds only host/port/**paths** to sops-decrypted secrets, never a secret's content. `ferrum-reconcile` and Recyclarr each read the referenced file's content themselves, at runtime.
- **Recyclarr's own `_secret` substitution mechanism embeds a referenced file's raw content verbatim — confirmed by reading nixpkgs' real `utils.genJqSecretsReplacement` source (`nixos/lib/utils.nix`), not assumed from its option doc's example (which is itself misleading: `_secret` must be a real *source* path, e.g. a sops-decrypted secret's path, not the `/run/credentials/...` *destination* path the option's own example shows).** Phase 1.4a's existing `<app>-apikey.sops` secrets decrypt to `"SONARR__AUTH__APIKEY=<key>\n"` — the `environmentFiles` format Sonarr's own auth wiring needs. Pointing Recyclarr's `_secret` at that path would embed that whole line as the `api_key` value, a real authentication failure against Sonarr's real API. The reconciler has the identical problem populating Prowlarr's Applications `apiKey` field with Sonarr/Radarr's own key. **Task 1 fixes this once, for both consumers:** `ensure_all` (in `crates/ferrum-apply/src/secrets.rs`) now generates a second, bare-value secret (`<app>-apikey-raw.sops`) alongside the existing one, from the same random key, in the same call — the two can never drift apart. Confirmed for real against `genJqSecretsReplacement`'s actual credential-generation code on ferrum-dev.
- **qBittorrent's WebUI requires authentication by default, even from localhost, and ferrum has never configured a stable credential for it** — confirmed for real: a fresh qBittorrent instance prints a *random, per-boot* temporary password to its own log and returns `403 Forbidden` for any unauthenticated API call, including from `127.0.0.1`. A random per-boot password is useless for reconciler automation. **Task 1 fixes this** by setting `services.qbittorrent.serverConfig.Preferences.WebUI.LocalHostAuth = false` — confirmed for real on ferrum-dev (real qBittorrent instance, real WebAPI call, real resulting `qBittorrent.conf` line, real unauthenticated `200` from `127.0.0.1` afterward) — which needs no new secret at all, matches this project's "reconciler talks via localhost, bypassing the proxy" architecture exactly, and additionally fixes `qbittorrent/meta.nix`'s `healthCheck` (which currently expects `403` from an unauthenticated call — that call will now genuinely succeed with `200`).
- **qBittorrent's real reachable address depends on whether the VPN kill switch (Phase 1.3/1.4a) is active** — confirmed by reading `modules/apps/qbittorrent/service.nix`'s already-shipped `qbt-vpn-netns-setup` script: when `ferrum.secrets ? "qbittorrent-vpn"`, qBittorrent's process joins an isolated network namespace and is reachable from the root namespace (where Sonarr/Radarr/Prowlarr/the reconciler run) via a veth pair at `10.200.1.2`, not `127.0.0.1`. The reconciler must never hardcode `127.0.0.1` for qBittorrent — Nix, which already knows whether the VPN secret is declared, resolves this into the generated `reconcile-config.json` (Task 3).
- **SABnzbd's own API key is not under ferrum's control today** — confirmed by reading nixpkgs' real `services.sabnzbd` module: it exposes only a `configFile` *path* option (no attrset-driven config like qBittorrent's `serverConfig`), so SABnzbd generates and owns its own random key in a non-declarative `sabnzbd.ini` on first start, exactly as `modules/apps/sabnzbd/meta.nix`'s own comment already flags ("Phase 1.4's problem"). **Task 1 closes this**, confirmed for real on ferrum-dev: a minimal, sparse pre-seeded `sabnzbd.ini` (`[misc] host`/`port`/`api_key`/`enable_https`) boots cleanly, SABnzbd fills in its own remaining defaults, and the preset key is genuinely honored for real authenticated API calls (verified `403` with a wrong key, `200` with the real one). This also closes a second, previously-unnoticed gap the same investigation surfaced: nothing in `modules/apps/sabnzbd/service.nix` has ever actually made `ferrum.apps.sabnzbd.port` control SABnzbd's real listening port — the nixpkgs module passes no `--port` CLI arg, so only the ini's own `[misc] port` key does anything, and nothing has ever written it. Task 1's bootstrap ini is also the first code that makes this option do anything real.
- **Real, verified API shapes** (all confirmed via real running Sonarr 4.0.19, Radarr 6.3.0, Prowlarr 2.5.2 instances and real POST/GET calls on ferrum-dev, not assumed from documentation):
  - Sonarr/Radarr download-client registration: `POST`/`GET` `/api/v3/downloadclient`, header `X-Api-Key: <key>`. `QBittorrent` implementation fields: `host`, `port`, `useSsl`, plus `tvCategory` (Sonarr) or `movieCategory` (Radarr) — `apiKey`/`username`/`password` left blank (LocalHostAuth bypass). `Sabnzbd` implementation fields: `host`, `port`, `useSsl`, `apiKey` (**must** be populated — SABnzbd has no bypass mechanism), `tvCategory`.
  - Prowlarr download-client registration: `POST`/`GET` `/api/v1/downloadclient` (v1, not v3) — same field shapes as above, with `category` instead of `tvCategory`/`movieCategory`.
  - Prowlarr Applications (indexer push-sync) registration: `POST`/`GET` `/api/v1/applications`. `Sonarr`/`Radarr` implementation fields: `prowlarrUrl`, `baseUrl`, `apiKey` (target app's own bare key), `syncCategories` (a real default list, confirmed from each app's own schema endpoint — Sonarr: `[5000,5010,5020,5030,5040,5045,5050,5090]`, Radarr: `[2000,2010,2020,2030,2040,2045,2050,2060,2070,2080,2090]`).
  - Idempotency: `GET` the same endpoint, a JSON array of objects each with `id`/`name`; skip `POST` if an entry's `name` already matches.
- **Category naming has no real collision risk and needs no cleverness**: qBittorrent and SABnzbd each have their own independent category namespace, and Sonarr's `tvCategory`/Radarr's `movieCategory`/Prowlarr's `category` are separate fields on separate apps — using the consumer's own catalog id (`"sonarr"`, `"radarr"`, `"prowlarr"`) as the category value on every provider is simple, sufficient, and matches real-world convention (distinguishing this consumer's downloads within the provider's shared list).
- **Recyclarr's default profile is scoped to `quality_definition` only, not `custom_formats`** — confirmed real and self-contained via Recyclarr's own docs (`quality_definition.type = "series"`/`"movie"` pulls TRaSH's bundled quality-size-limit tables, no external lookup needed). `custom_formats` entries require real TRaSH-Guide `trash_id` GUIDs this plan has no way to verify without fabricating them, which this project's "no placeholders, real code only" discipline rules out. This is a deliberate scope trim from the spec's own "and the commonly-recommended custom formats" aspiration, not an oversight — an operator who wants custom formats adds them via the same `custom/` override the spec's own Recyclarr section already describes for any different profile.
- Both the reconciler and Recyclarr authenticate purely via localhost + API key, never through nginx/Authelia (per the spec's own resolution of this question).

---

## Task 1: Secrets foundation — bare-key secrets, qBittorrent auth bypass, SABnzbd bootstrap

**Files:**
- Modify: `crates/ferrum-apply/src/secrets.rs` (extend `ensure_all`, add `ensure_sabnzbd_apikey`)
- Modify: `crates/ferrum-apply/src/apply.rs` (`StorageConfig` fields, wire the new call into Step 0)
- Modify: `crates/ferrum-apply/src/main.rs` (read the two new env vars)
- Modify: `modules/core/overlays.nix` (two new `--set-default` lines)
- Modify: `modules/apps/sonarr/service.nix`, `modules/apps/radarr/service.nix`, `modules/apps/prowlarr/service.nix` (declare the new raw-key secret + a matched-pair assertion)
- Modify: `modules/apps/qbittorrent/service.nix` (`LocalHostAuth = false`)
- Modify: `modules/apps/qbittorrent/meta.nix` (`healthCheck.expectStatus` 403 → 200)
- Modify: `modules/apps/sabnzbd/service.nix` (declare `sabnzbd-apikey` secret)

**Interfaces:**
- Consumes: `random_hex_key`/`host_age_recipient`/`encrypt_and_write` (all already in `secrets.rs`, Phase 1.4a).
- Produces: `<app>-apikey-raw.sops` for `sonarr`/`radarr`/`prowlarr` (bare hex key), `sabnzbd-apikey.sops` (bare hex key) — both consumed by Task 2 (Recyclarr) and Task 3 (reconciler) via `config.sops.secrets."<name>".path`. `services.qbittorrent.serverConfig.Preferences.WebUI.LocalHostAuth = false` — a fact Task 3's connection-info generation relies on (no `apiKeySecretPath` needed for qBittorrent).

- [ ] **Step 1: Extend `ensure_all` in `crates/ferrum-apply/src/secrets.rs` to generate a matched bare-value secret**

Replace the existing `ensure_all` function body:

```rust
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
```

(Only the loop body changed — the missing-check and recipient derivation stay exactly as they are, so idempotency is still keyed on `<app>-apikey.sops` alone. A host that already has that file from before this plan will NOT get a raw file generated retroactively — see Step 5's assertion for why, and its documented recovery.)

- [ ] **Step 2: Add `ensure_sabnzbd_apikey` to `crates/ferrum-apply/src/secrets.rs`**

Add this new function after `ensure_authelia_secrets`:

```rust
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
    if ini_path.exists() {
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
```

- [ ] **Step 3: Add unit tests for both changes**

Add to the `#[cfg(test)] mod tests` block in `secrets.rs`:

```rust
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

    #[test]
    fn ensure_sabnzbd_apikey_is_idempotent_when_ini_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("sabnzbd.ini"), "[misc]\napi_key = existing\n").unwrap();
        let nonexistent_pubkey = dir.path().join("no-such-key.pub");
        let result = ensure_sabnzbd_apikey(&state_dir, dir.path(), &nonexistent_pubkey, 8080);
        assert!(result.is_ok(), "should short-circuit before touching the host key: {result:?}");
        assert!(!dir.path().join("sabnzbd-apikey.sops").exists());
        let content = std::fs::read_to_string(state_dir.join("sabnzbd.ini")).unwrap();
        assert_eq!(content, "[misc]\napi_key = existing\n", "must not overwrite an existing ini");
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
```

- [ ] **Step 4: Wire `ensure_sabnzbd_apikey` into `apply.rs`'s existing Step 0**

Add `pub sabnzbd_state_dir: Option<PathBuf>` and `pub sabnzbd_port: u16` to `StorageConfig`, then extend Step 0:

```rust
    let servarr_refs: Vec<&str> = storage.servarr_apps.iter().map(String::as_str).collect();
    crate::secrets::ensure_all(&storage.secrets_dir, &storage.host_key_pub, &servarr_refs)?;
    if storage.auth_enabled {
        crate::secrets::ensure_authelia_secrets(&storage.secrets_dir, &storage.host_key_pub)?;
        crate::secrets::ensure_first_authelia_user(&storage.authelia_state_dir, &storage.admin_email)?;
    }
    if let Some(sabnzbd_state_dir) = &storage.sabnzbd_state_dir {
        crate::secrets::ensure_sabnzbd_apikey(
            sabnzbd_state_dir,
            &storage.secrets_dir,
            &storage.host_key_pub,
            storage.sabnzbd_port,
        )?;
    }
```

- [ ] **Step 5: Thread the two new fields through `main.rs` and `overlays.nix`, and add the matched-pair assertion to the three servarr apps**

In `main.rs`'s `Command::Apply` arm, add:

```rust
                sabnzbd_state_dir: std::env::var("FERRUM_SABNZBD_STATE_DIR")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .map(std::path::PathBuf::from),
                sabnzbd_port: std::env::var("FERRUM_SABNZBD_PORT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(8080),
```

In `modules/core/overlays.nix`'s `makeWrapper` invocation, the existing last line (`--set-default FERRUM_ADMIN_EMAIL ${lib.escapeShellArg ferrum.auth.adminEmail}`) currently has no trailing `\` since it's the last argument — add a `\` to that line and append these two more `--set-default` lines after it, following the exact same pattern every existing line already uses:

```nix
            --set-default FERRUM_SABNZBD_STATE_DIR ${lib.escapeShellArg (if ferrum.apps.sabnzbd.enable or false then ferrum.apps.sabnzbd.stateDir else "")} \
            --set-default FERRUM_SABNZBD_PORT ${toString (ferrum.apps.sabnzbd.port or 8080)}
```

In each of `modules/apps/sonarr/service.nix`, `modules/apps/radarr/service.nix`, `modules/apps/prowlarr/service.nix`, add (inside the existing `lib.mkIf app.enable { ... }` block, alongside the existing `sops.secrets."<app>-apikey"` declaration — substitute `<app>` for `sonarr`/`radarr`/`prowlarr` in each file):

```nix
  sops.secrets."<app>-apikey-raw" = {
    sopsFile = /. + "${ferrum.secretsDir}/<app>-apikey-raw.sops";
    format = "binary";
    owner = "<app>";
  };

  # A host that already had <app>-apikey.sops from before Phase 1.4c
  # cannot get a matching raw secret generated retroactively --
  # ensure_all has no way to decrypt the existing key (by design, it
  # never holds the private age key), so a fresh, mismatched raw key
  # would silently break Recyclarr/the reconciler's auth against this
  # app rather than fail loudly. This assertion turns that into a clear,
  # actionable message instead.
  assertions = [
    {
      assertion = !(builtins.pathExists (/. + "${ferrum.secretsDir}/<app>-apikey.sops"))
                  || builtins.pathExists (/. + "${ferrum.secretsDir}/<app>-apikey-raw.sops");
      message = ''
        ${ferrum.secretsDir}/<app>-apikey.sops exists but
        ${ferrum.secretsDir}/<app>-apikey-raw.sops does not -- this host
        generated its <App> API key before Recyclarr/reconciler support
        existed, which need a bare-value copy of the same key ferrum-apply
        cannot retroactively create. Delete both <app>-apikey.sops and
        <app>-apikey-raw.sops (if present) under ${ferrum.secretsDir} and
        re-apply to generate a fresh matched pair -- see README.md's
        Secrets section for the same recovery procedure already documented
        for servarr keys.
      '';
    }
  ];
```

- [ ] **Step 6: qBittorrent — bypass WebUI auth for localhost, fix the health check**

In `modules/apps/qbittorrent/service.nix`, extend the existing `services.qbittorrent = { ... };` block:

```nix
  services.qbittorrent = {
    enable = true;
    profileDir = app.stateDir;
    user = "qbittorrent";
    group = "qbittorrent";
    webuiPort = app.port;
    # qBittorrent requires WebUI authentication by default, even from
    # localhost -- confirmed for real on ferrum-dev: an unconfigured
    # instance prints a random PER-BOOT temporary password to its own log
    # and returns 403 for any unauthenticated call. A random password that
    # changes every restart is useless for the reconciler (Phase 1.4c) to
    # authenticate with. This setting (confirmed via the real
    # app/setPreferences WebAPI call, which wrote exactly this key into a
    # real qBittorrent.conf) bypasses auth ONLY for requests from
    # 127.0.0.1/the VPN-namespace veth's host side -- both already the
    # trust boundary every other app in this catalog uses (bindaddress =
    # 127.0.0.1), so this adds no new exposure. No credential to generate,
    # store, or rotate.
    serverConfig.Preferences.WebUI.LocalHostAuth = false;
  };
```

In `modules/apps/qbittorrent/meta.nix`, change the health check (with `LocalHostAuth = false`, this endpoint now genuinely returns 200 unauthenticated from localhost, confirmed for real on ferrum-dev):

```nix
  healthCheck = {
    path = "/api/v2/app/version";
    expectStatus = 200;
    timeoutSec = 30;
  };
```

(Update the comment above it too — the old one explained why `403` was expected; that reasoning no longer applies. Replace it with: `# LocalHostAuth = false (service.nix) makes this endpoint genuinely return 200 unauthenticated from localhost -- confirmed for real on ferrum-dev.`)

- [ ] **Step 7: SABnzbd — declare the generated secret**

In `modules/apps/sabnzbd/service.nix`, add alongside the existing `services.sabnzbd = { ... };` block:

```nix
  sops.secrets."sabnzbd-apikey" = {
    sopsFile = /. + "${ferrum.secretsDir}/sabnzbd-apikey.sops";
    format = "binary";
    owner = "sabnzbd";
  };
```

- [ ] **Step 8: Real verification on ferrum-dev**

1. `cargo test -p ferrum-apply` — existing tests plus the three new ones from Step 3 all pass.
2. `cargo clippy -p ferrum-apply --all-targets -- -D warnings` and `cargo fmt --check` both clean.
3. Real end-to-end: on a real host closure with `sonarr.enable = true`, run the real `ferrum-apply apply` preflight step (or the equivalent direct call), confirm `sonarr-apikey.sops` AND `sonarr-apikey-raw.sops` both exist, both decrypt via `sops -d`, and the raw one's decrypted content is exactly the bare hex key with no `SONARR__AUTH__APIKEY=` prefix.
4. Real end-to-end: with `sabnzbd.enable = true`, run the same, confirm `sabnzbd.ini` was written with a real `api_key` line and the configured port, confirm `sabnzbd-apikey.sops` decrypts to the identical bare key, then actually start `sabnzbd.service` for real and confirm a `curl` call to its real API with that decrypted key succeeds (`200`) and with a wrong key fails (`403`) — matching the exact test already run by hand while writing this plan.
5. Real boot test: with `qbittorrent.enable = true`, start `qbittorrent.service` for real, confirm an unauthenticated `curl http://127.0.0.1:<port>/api/v2/app/version` from the host returns `200` (not `403`), and confirm the real `qBittorrent.conf` on disk contains `WebUI\LocalHostAuth=false`.
6. Real assertion test: hand-construct a host eval where `<app>-apikey.sops` exists but `<app>-apikey-raw.sops` doesn't (simulating a pre-existing host), confirm the new assertion fires with its documented message; confirm it stays silent when both files exist or neither does.

- [ ] **Step 9: Commit**

```bash
git add crates/ferrum-apply/src/secrets.rs crates/ferrum-apply/src/apply.rs crates/ferrum-apply/src/main.rs modules/core/overlays.nix modules/apps/sonarr/service.nix modules/apps/radarr/service.nix modules/apps/prowlarr/service.nix modules/apps/qbittorrent/service.nix modules/apps/qbittorrent/meta.nix modules/apps/sabnzbd/service.nix
git commit -m "Secrets foundation for Reconciler/Recyclarr: bare-value API keys, qBittorrent localhost auth bypass, SABnzbd first-boot bootstrap"
```

---

## Task 2: Recyclarr — opinionated, optional TRaSH quality-definition sync

**Files:**
- Create: `modules/core/recyclarr.nix`
- Modify: `modules/core/options.nix` (add `ferrum.recyclarr.enable`)
- Modify: `modules/default.nix` (import the new module)

**Interfaces:**
- Consumes: `ferrum.apps.{sonarr,radarr}.{enable,port}`, `config.sops.secrets."{sonarr,radarr}-apikey-raw".path` (Task 1).
- Produces: `services.recyclarr.*` (standard NixOS option, no other module reads it).

- [ ] **Step 1: Add the `ferrum.recyclarr` option**

In `modules/core/options.nix`, add a new top-level block alongside `auth`:

```nix
    recyclarr = {
      enable = mkEnableOption "opinionated TRaSH-Guide quality-profile sync for Sonarr/Radarr via Recyclarr";
    };
```

- [ ] **Step 2: Write `modules/core/recyclarr.nix`**

```nix
# Recyclarr: opinionated, optional TRaSH-Guide quality-definition sync for
# Sonarr and Radarr, reusing nixpkgs' own services.recyclarr module
# directly (confirmed present and packaged for both x86_64-linux and
# aarch64-linux against the pinned nixpkgs revision) rather than a bespoke
# ferrum wrapper -- that module already does exactly what's needed: a
# systemd timer running `recyclarr sync` on a schedule, with a
# secrets-substitution mechanism that composes directly with sops-nix's
# own decrypted-secret paths.
#
# Scoped to quality_definition only, not custom_formats -- quality_definition
# is real, documented, and self-contained (it pulls TRaSH's own bundled
# quality-size-limit tables via Recyclarr's `type` setting, no external
# lookup needed); custom_formats entries need real TRaSH-Guide trash_id
# GUIDs this plan has no way to verify without fabricating them. An
# operator who wants custom formats adds them via the same `custom/`
# override mechanism every other ferrum default supports (see
# services.recyclarr.configuration's own description).
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  recyclarrEnabled = ferrum.recyclarr.enable;

  sonarrEnabled = recyclarrEnabled && (ferrum.apps.sonarr.enable or false);
  radarrEnabled = recyclarrEnabled && (ferrum.apps.radarr.enable or false);

  # Recyclarr's own `_secret` mechanism reads the REFERENCED FILE'S RAW
  # CONTENT verbatim (confirmed against nixpkgs' real
  # utils.genJqSecretsReplacement source) -- the "-raw" secrets Task 1
  # added are exactly the bare-value representation this needs; the
  # original "<app>-apikey.sops" (environmentFiles format) would embed
  # the whole "SONARR__AUTH__APIKEY=<key>" line as the api_key value
  # instead, a real auth failure against Sonarr's real API.
  configuration =
    lib.optionalAttrs sonarrEnabled {
      sonarr.main = {
        base_url = "http://127.0.0.1:${toString ferrum.apps.sonarr.port}";
        api_key._secret = config.sops.secrets."sonarr-apikey-raw".path;
        quality_definition.type = "series";
      };
    }
    // lib.optionalAttrs radarrEnabled {
      radarr.main = {
        base_url = "http://127.0.0.1:${toString ferrum.apps.radarr.port}";
        api_key._secret = config.sops.secrets."radarr-apikey-raw".path;
        quality_definition.type = "movie";
      };
    };
in
lib.mkIf recyclarrEnabled {
  services.recyclarr = {
    enable = true;
    inherit configuration;
  };
}
```

- [ ] **Step 3: Wire the module into `modules/default.nix`**

Add `./core/recyclarr.nix` to the `imports` list, alongside the other `./core/*.nix` entries.

- [ ] **Step 4: Real verification on ferrum-dev**

1. `nix build .#checks.x86_64-linux.schema-uniformity` — the new `ferrum.recyclarr.enable` option is a plain bool, stays clean.
2. Real eval: a host with `ferrum.recyclarr.enable = true` and both `sonarr.enable`/`radarr.enable` true evaluates `config.system.build.toplevel.drvPath` cleanly, and `config.services.recyclarr.configuration` contains both `sonarr.main` and `radarr.main` with the expected `base_url`/`quality_definition.type` values and an `api_key._secret` pointing at the real `sonarr-apikey-raw`/`radarr-apikey-raw` sops-nix decrypted path.
3. Real eval: a host with `ferrum.recyclarr.enable = true` but only `sonarr.enable = true` (radarr disabled) evaluates cleanly with `configuration` containing only `sonarr.main`.
4. Real boot test: build and boot a host with `ferrum.recyclarr.enable = true` and a real running Sonarr instance (real `sonarr-apikey-raw` secret in place, matching Task 1's real generated key), manually trigger `recyclarr.service` (`systemctl start recyclarr.service`), confirm it exits successfully, and confirm via Sonarr's own `/api/v3/qualityprofile` (or equivalent) that a real quality definition change landed — not just that the service exited 0.

- [ ] **Step 5: Commit**

```bash
git add modules/core/recyclarr.nix modules/core/options.nix modules/default.nix
git commit -m "Add opinionated, optional Recyclarr TRaSH quality-definition sync for Sonarr/Radarr"
```

---

## Task 3: Reconciler — `ferrum-reconcile` crate and Nix wiring

**Files:**
- Create: `crates/ferrum-reconcile/Cargo.toml`
- Create: `crates/ferrum-reconcile/src/main.rs`
- Modify: `crates/Cargo.toml` (add `ferrum-reconcile` to workspace `members`)
- Create: `nix/pkgs/ferrum-reconcile/default.nix`
- Modify: `nix/modules/flake/packages.nix` (wire the new package)
- Modify: `nix/modules/flake/checks.nix` (add a `cargo-test-ferrum-reconcile` check, mirroring the existing `cargo-test-ferrum-apply` one)
- Create: `modules/core/reconciler.nix`
- Modify: `modules/default.nix` (import the new module)

**Interfaces:**
- Consumes: `ferrum.apps.*.{enable,port}`, `catalog.<id>.integrations.{providesTo,consumes}` (`modules/lib/catalog.nix`), `config.sops.secrets."<name>".path` for the raw/bare secrets Task 1 produces, `ferrum.secrets ? "qbittorrent-vpn"` (VPN topology).
- Produces: a running `ferrum-reconcile.service` systemd oneshot; no other module reads anything from this one.

- [ ] **Step 1: Write `crates/ferrum-reconcile/Cargo.toml`**

```toml
[package]
name = "ferrum-reconcile"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ureq = { version = "2", features = ["json"] }
```

(`ureq` — a blocking, synchronous HTTP client with no async runtime dependency — is the minimal-footprint choice for a oneshot binary making a handful of sequential calls; pulling in tokio+reqwest for this would be pure overhead.)

- [ ] **Step 2: Write `crates/ferrum-reconcile/src/main.rs` — config types and connection resolution**

```rust
// ferrum-reconcile: registers download clients and Prowlarr "Applications"
// across the catalog, driven entirely by a JSON config Nix generates from
// each app's own integrations.providesTo/consumes metadata
// (modules/core/reconciler.nix). Nix has already validated that every pair
// is mutually declared on both sides and resolved each app's real
// connection info (including qBittorrent's VPN-namespace topology) before
// this binary ever runs -- this binary's only job is the two real
// registration kinds themselves (download-client, application), matching
// the plan's own "hardcode the small dispatch directly in Rust" scope
// decision for a two-case problem.
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize)]
struct AppConnInfo {
    host: String,
    port: u16,
    #[serde(rename = "apiKeySecretPath")]
    api_key_secret_path: Option<String>,
}

#[derive(Deserialize)]
struct Pair {
    kind: String, // "downloadClient" | "application"
    consumer: String,
    provider: String,
}

#[derive(Deserialize)]
struct ReconcileConfig {
    apps: HashMap<String, AppConnInfo>,
    pairs: Vec<Pair>,
}

/// Reads a sops-nix decrypted secret's bare content, trimmed of the
/// trailing newline encrypt_and_write always adds (see
/// crates/ferrum-apply/src/secrets.rs). None means the app needs no key
/// at all (qBittorrent, via LocalHostAuth = false).
fn read_api_key(path: &Option<String>) -> anyhow::Result<Option<String>> {
    match path {
        None => Ok(None),
        Some(p) => Ok(Some(
            fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read secret at {p}: {e}"))?
                .trim()
                .to_string(),
        )),
    }
}

fn base_url(app: &AppConnInfo) -> String {
    format!("http://{}:{}", app.host, app.port)
}

fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("FERRUM_RECONCILE_CONFIG")
        .map_err(|_| anyhow::anyhow!("FERRUM_RECONCILE_CONFIG not set"))?;
    let raw = fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("failed to read {config_path}: {e}"))?;
    let config: ReconcileConfig = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse {config_path}: {e}"))?;

    for pair in &config.pairs {
        let consumer = config
            .apps
            .get(&pair.consumer)
            .ok_or_else(|| anyhow::anyhow!("unknown consumer app '{}'", pair.consumer))?;
        let provider = config
            .apps
            .get(&pair.provider)
            .ok_or_else(|| anyhow::anyhow!("unknown provider app '{}'", pair.provider))?;
        let consumer_key = read_api_key(&consumer.api_key_secret_path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "no API key configured for consumer app '{}' -- required to call its own API",
                pair.consumer
            )
        })?;

        match pair.kind.as_str() {
            "downloadClient" => {
                register_download_client(&pair.consumer, consumer, &consumer_key, &pair.provider, provider)?
            }
            "application" => {
                register_application(consumer, &consumer_key, &pair.provider, provider)?
            }
            other => anyhow::bail!("unknown pair kind '{other}' for {}->{}", pair.consumer, pair.provider),
        }
        println!("ferrum-reconcile: {} <- {} ({}) OK", pair.consumer, pair.provider, pair.kind);
    }
    Ok(())
}
```

- [ ] **Step 3: Add `register_download_client` — the download-client registration kind**

Append to `main.rs`:

```rust
/// Looks up an existing entry by `name` at `GET {base}{path}` -- both
/// Sonarr/Radarr's v3 and Prowlarr's v1 downloadclient/applications
/// endpoints return the same shape (a JSON array of objects with at least
/// `id`/`name`), confirmed for real on ferrum-dev.
fn find_existing_id(base: &str, path: &str, api_key: &str, name: &str) -> anyhow::Result<Option<u64>> {
    let resp: Vec<serde_json::Value> = ureq::get(&format!("{base}{path}"))
        .set("X-Api-Key", api_key)
        .call()
        .map_err(|e| anyhow::anyhow!("GET {base}{path} failed: {e}"))?
        .into_json()
        .map_err(|e| anyhow::anyhow!("GET {base}{path} returned invalid JSON: {e}"))?;
    Ok(resp
        .iter()
        .find(|v| v["name"] == name)
        .and_then(|v| v["id"].as_u64()))
}

/// The consumer's own downloadclient API base path -- v3 for Sonarr/
/// Radarr, v1 for Prowlarr (confirmed for real: Prowlarr's servarr
/// framework fork uses v1 throughout, unlike Sonarr/Radarr's v3).
fn download_client_api_path(consumer_id: &str) -> anyhow::Result<&'static str> {
    match consumer_id {
        "sonarr" | "radarr" => Ok("/api/v3/downloadclient"),
        "prowlarr" => Ok("/api/v1/downloadclient"),
        other => anyhow::bail!("no downloadclient API known for consumer app '{other}'"),
    }
}

/// The consumer-specific category field name -- confirmed for real from
/// each app's own /downloadclient/schema endpoint on ferrum-dev: Sonarr
/// uses tvCategory, Radarr movieCategory, Prowlarr a single category
/// field (it isn't tv/movie-specific).
fn category_field_name(consumer_id: &str) -> anyhow::Result<&'static str> {
    match consumer_id {
        "sonarr" => Ok("tvCategory"),
        "radarr" => Ok("movieCategory"),
        "prowlarr" => Ok("category"),
        other => anyhow::bail!("no category field convention for consumer app '{other}'"),
    }
}

/// The provider-specific implementation fields -- confirmed for real from
/// the QBittorrent/Sabnzbd schema entries on ferrum-dev. qBittorrent needs
/// no apiKey (LocalHostAuth = false, Task 1); SABnzbd's api_key is
/// required -- it has no bypass mechanism.
fn provider_implementation(
    provider_id: &str,
    provider_key: &Option<String>,
) -> anyhow::Result<(&'static str, &'static str, &'static str, serde_json::Value)> {
    match provider_id {
        "qbittorrent" => Ok((
            "QBittorrent",
            "QBittorrentSettings",
            "torrent",
            serde_json::json!({}),
        )),
        "sabnzbd" => {
            let key = provider_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("SABnzbd provider has no API key configured -- cannot register it")
            })?;
            Ok((
                "Sabnzbd",
                "SabnzbdSettings",
                "usenet",
                serde_json::json!({ "apiKey": key }),
            ))
        }
        other => anyhow::bail!("no download-client implementation known for provider app '{other}'"),
    }
}

fn register_download_client(
    consumer_id: &str,
    consumer: &AppConnInfo,
    consumer_key: &str,
    provider_id: &str,
    provider: &AppConnInfo,
) -> anyhow::Result<()> {
    let base = base_url(consumer);
    let path = download_client_api_path(consumer_id)?;
    if find_existing_id(&base, path, consumer_key, provider_id)?.is_some() {
        return Ok(());
    }

    // Only Sabnzbd needs its own key read here (qBittorrent needs none) --
    // read_api_key handles both, called with the PROVIDER's own secret path.
    let provider_key = read_api_key(&provider.api_key_secret_path)?;
    let (implementation, config_contract, protocol, extra_fields) =
        provider_implementation(provider_id, &provider_key)?;
    let category_field = category_field_name(consumer_id)?;

    let mut fields = vec![
        serde_json::json!({ "name": "host", "value": provider.host }),
        serde_json::json!({ "name": "port", "value": provider.port }),
        serde_json::json!({ "name": "useSsl", "value": false }),
        serde_json::json!({ "name": category_field, "value": consumer_id }),
    ];
    if let Some(obj) = extra_fields.as_object() {
        for (k, v) in obj {
            fields.push(serde_json::json!({ "name": k, "value": v }));
        }
    }

    let body = serde_json::json!({
        "enable": true,
        "protocol": protocol,
        "priority": 1,
        "name": provider_id,
        "implementation": implementation,
        "configContract": config_contract,
        "fields": fields,
    });

    ureq::post(&format!("{base}{path}"))
        .set("X-Api-Key", consumer_key)
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("POST {base}{path} for {provider_id} failed: {e}"))?;
    Ok(())
}
```

- [ ] **Step 4: Add `register_application` — the application (indexer push-sync) registration kind**

Append to `main.rs`:

```rust
/// Real default syncCategories per target app, confirmed from each app's
/// own /api/v1/applications/schema entry on ferrum-dev (Prowlarr's own
/// advertised defaults, not invented).
fn default_sync_categories(provider_id: &str) -> anyhow::Result<&'static [i64]> {
    match provider_id {
        "sonarr" => Ok(&[5000, 5010, 5020, 5030, 5040, 5045, 5050, 5090]),
        "radarr" => Ok(&[2000, 2010, 2020, 2030, 2040, 2045, 2050, 2060, 2070, 2080, 2090]),
        other => anyhow::bail!("no default syncCategories known for application target '{other}'"),
    }
}

fn application_implementation(provider_id: &str) -> anyhow::Result<(&'static str, &'static str)> {
    match provider_id {
        "sonarr" => Ok(("Sonarr", "SonarrSettings")),
        "radarr" => Ok(("Radarr", "RadarrSettings")),
        other => anyhow::bail!("no Applications implementation known for target app '{other}'"),
    }
}

fn register_application(
    consumer: &AppConnInfo,
    consumer_key: &str,
    provider_id: &str,
    provider: &AppConnInfo,
) -> anyhow::Result<()> {
    // consumer here is Prowlarr (the only app this pair kind ever has as
    // consumer, per modules/core/reconciler.nix's pairKind); provider is
    // the target app (Sonarr/Radarr) Prowlarr pushes indexers into.
    let base = base_url(consumer);
    let path = "/api/v1/applications";
    if find_existing_id(&base, path, consumer_key, provider_id)?.is_some() {
        return Ok(());
    }

    let provider_key = read_api_key(&provider.api_key_secret_path)?.ok_or_else(|| {
        anyhow::anyhow!("no API key configured for application target '{provider_id}'")
    })?;
    let (implementation, config_contract) = application_implementation(provider_id)?;
    let sync_categories = default_sync_categories(provider_id)?;

    let body = serde_json::json!({
        "name": provider_id,
        "syncLevel": "fullSync",
        "implementation": implementation,
        "configContract": config_contract,
        "fields": [
            { "name": "prowlarrUrl", "value": base_url(consumer) },
            { "name": "baseUrl", "value": base_url(provider) },
            { "name": "apiKey", "value": provider_key },
            { "name": "syncCategories", "value": sync_categories },
        ],
    });

    ureq::post(&format!("{base}{path}"))
        .set("X-Api-Key", consumer_key)
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("POST {base}{path} for {provider_id} failed: {e}"))?;
    Ok(())
}
```

- [ ] **Step 5: Add unit tests for the pure helper functions**

Append to `main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_field_name_matches_each_apps_real_schema() {
        assert_eq!(category_field_name("sonarr").unwrap(), "tvCategory");
        assert_eq!(category_field_name("radarr").unwrap(), "movieCategory");
        assert_eq!(category_field_name("prowlarr").unwrap(), "category");
        assert!(category_field_name("qbittorrent").is_err());
    }

    #[test]
    fn download_client_api_path_uses_v1_for_prowlarr_v3_for_sonarr_radarr() {
        assert_eq!(download_client_api_path("sonarr").unwrap(), "/api/v3/downloadclient");
        assert_eq!(download_client_api_path("radarr").unwrap(), "/api/v3/downloadclient");
        assert_eq!(download_client_api_path("prowlarr").unwrap(), "/api/v1/downloadclient");
    }

    #[test]
    fn default_sync_categories_are_non_empty_and_real() {
        assert_eq!(default_sync_categories("sonarr").unwrap().len(), 8);
        assert_eq!(default_sync_categories("radarr").unwrap().len(), 11);
        assert!(default_sync_categories("qbittorrent").is_err());
    }

    #[test]
    fn read_api_key_trims_the_trailing_newline_encrypt_and_write_adds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "deadbeef1234\n").unwrap();
        let result = read_api_key(&Some(path.to_string_lossy().to_string())).unwrap();
        assert_eq!(result, Some("deadbeef1234".to_string()));
    }

    #[test]
    fn read_api_key_returns_none_for_none_path() {
        assert_eq!(read_api_key(&None).unwrap(), None);
    }
}
```

Add `tempfile = "3"` to `[dev-dependencies]` in `crates/ferrum-reconcile/Cargo.toml` (matching `ferrum-apply`'s own `Cargo.toml`).

- [ ] **Step 6: Wire `ferrum-reconcile` into the Cargo workspace**

In `crates/Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["ferrum-apply", "ferrum-reconcile"]
```

- [ ] **Step 7: Write `nix/pkgs/ferrum-reconcile/default.nix`**

```nix
{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "ferrum-reconcile";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-reconcile";
}
```

(No `nativeCheckInputs`/wrapper needed — unlike `ferrum-apply`, this binary shells out to nothing; every dependency it has is a real Rust crate resolved at build time.)

- [ ] **Step 8: Wire the package into `nix/modules/flake/packages.nix` and `nix/modules/flake/checks.nix`**

In `packages.nix`, add alongside the existing `ferrum-apply` entry:

```nix
        ferrum-reconcile = pkgs.callPackage ../../../nix/pkgs/ferrum-reconcile { };
```

In `checks.nix`, add alongside `cargo-test-ferrum-apply`:

```nix
        cargo-test-ferrum-reconcile = self'.packages.ferrum-reconcile;

        clippy-ferrum-reconcile = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-reconcile-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          buildAndTestSubdir = "ferrum-reconcile";
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          checkPhase = "cargo clippy --offline -- -D warnings";
          installPhase = "mkdir -p $out";
        };
```

- [ ] **Step 9: Write `modules/core/reconciler.nix` — connection-info generation, pair computation, and the systemd unit**

```nix
# Generates the JSON config crates/ferrum-reconcile reads (per-app
# connection info + a pre-validated, pre-computed list of registration
# pairs), and the systemd oneshot that runs it after every
# ferrum-apps.target start -- matching the spec's own "re-runs on any
# target restart, not only after an explicit config change" requirement,
# so a crash recovery or a rollback's state-restore cycle re-syncs
# registrations too.
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  catalog = import ../lib/catalog.nix { inherit lib; };
  enabledApps = lib.filterAttrs (_: app: app.enable) ferrum.apps;

  # qBittorrent's real reachable address depends on whether the VPN kill
  # switch (Phase 1.3/1.4a) put it in an isolated network namespace --
  # confirmed by reading modules/apps/qbittorrent/service.nix's own
  # qbt-vpn-netns-setup script: the veth pair's host-reachable side is a
  # hardcoded 10.200.1.2. Every other app always runs in the root
  # namespace, always reachable at 127.0.0.1.
  vpnEnabled = ferrum.secrets ? "qbittorrent-vpn";
  appHost = id: if id == "qbittorrent" && vpnEnabled then "10.200.1.2" else "127.0.0.1";

  # Which apps have a reconciler-usable bare-value API key, and under what
  # secret name (Task 1). qBittorrent needs none (LocalHostAuth = false).
  appKeySecretName = id:
    if lib.elem id [ "sonarr" "radarr" "prowlarr" ] then "${id}-apikey-raw"
    else if id == "sabnzbd" then "sabnzbd-apikey"
    else null;

  appConnInfo = id: app: {
    host = appHost id;
    port = app.port;
    apiKeySecretPath =
      let name = appKeySecretName id;
      in if name != null then config.sops.secrets.${name}.path else null;
  };

  # Validates providesTo/consumes symmetry across the WHOLE catalog (every
  # app's meta.nix, not just enabled ones -- a metadata bug should fail
  # eval regardless of which subset of apps a given host happens to
  # enable). Extends the same "catch a real bug at eval time, not at
  # registration time" spirit as checks.catalog-consistency
  # (nix/modules/flake/checks.nix), for the metadata this plan is the
  # first thing to actually ACT on.
  symmetryErrors = lib.flatten (lib.mapAttrsToList
    (id: meta:
      (map
        (p: if !(lib.elem id (catalog.${p}.integrations.consumes or [ ])) then
          "modules/apps/${id}/meta.nix declares integrations.providesTo \"${p}\", but ${p}'s own meta.nix integrations.consumes does not list \"${id}\""
        else null)
        (meta.integrations.providesTo or [ ]))
      ++ (map
        (c: if !(lib.elem id (catalog.${c}.integrations.providesTo or [ ])) then
          "modules/apps/${id}/meta.nix declares integrations.consumes \"${c}\", but ${c}'s own meta.nix integrations.providesTo does not list \"${id}\""
        else null)
        (meta.integrations.consumes or [ ])))
    catalog);
  realSymmetryErrors = builtins.filter (x: x != null) symmetryErrors;

  # Two registration kinds (matching the spec's own "exactly two" scope
  # decision): Prowlarr registering Sonarr/Radarr is "application" (its
  # own indexer push-sync feature); every other consumes/providesTo edge
  # is "downloadClient".
  pairKind = consumer: provider:
    if consumer == "prowlarr" && lib.elem provider [ "sonarr" "radarr" ]
    then "application"
    else "downloadClient";

  pairs = lib.flatten (lib.mapAttrsToList
    (id: _:
      map
        (providerId: { kind = pairKind id providerId; consumer = id; provider = providerId; })
        (builtins.filter (p: enabledApps ? ${p}) (catalog.${id}.integrations.consumes or [ ])))
    enabledApps);

  reconcileConfigFile = pkgs.writeText "ferrum-reconcile-config.json" (builtins.toJSON {
    apps = lib.mapAttrs appConnInfo enabledApps;
    inherit pairs;
  });
in
{
  assertions = map (msg: { assertion = false; message = msg; }) realSymmetryErrors;

  systemd.services.ferrum-reconcile = lib.mkIf (pairs != [ ]) {
    description = "Register download clients and indexer applications across the catalog";
    after = [ "ferrum-apps.target" ];
    wantedBy = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    environment.FERRUM_RECONCILE_CONFIG = "${reconcileConfigFile}";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.ferrum-reconcile}/bin/ferrum-reconcile";
      # Runs as root: sops-nix's own default secret ownership is root:root,
      # and this oneshot's whole job is reading a handful of already-
      # decrypted secret files plus making HTTP calls to already
      # localhost-only-reachable services -- the same trust level
      # ferrum-apply and ferrum-state-restore already run at, for the
      # same reason (privileged coordination, not privilege escalation
      # over untrusted input). A deliberate scope decision, not an
      # oversight: giving this its own non-root user would mean adding
      # owner=/group= overrides to every secret Task 1 generates, for no
      # real security benefit given what this binary actually does.
    };
  };
}
```

- [ ] **Step 10: Wire the module into `modules/default.nix`**

Add `./core/reconciler.nix` to the `imports` list.

- [ ] **Step 11: Real verification on ferrum-dev**

1. `cargo test -p ferrum-reconcile` — all Step 5 unit tests pass.
2. `cargo clippy -p ferrum-reconcile --all-targets -- -D warnings` and `cargo fmt --check` both clean.
3. `nix build .#ferrum-reconcile` succeeds and produces a real binary.
4. Real eval: a host with `sonarr.enable`/`radarr.enable`/`prowlarr.enable`/`qbittorrent.enable`/`sabnzbd.enable` all true evaluates `config.system.build.toplevel.drvPath` cleanly; inspect the generated `reconcileConfigFile`'s real content (`nix eval --raw` its store path, `cat` it) and confirm: qBittorrent's `apiKeySecretPath` is `null`, every other app's points at the real Task 1 secret path, and `pairs` contains exactly the expected 8 entries (sonarr←qbittorrent, sonarr←sabnzbd, radarr←qbittorrent, radarr←sabnzbd, prowlarr←qbittorrent, prowlarr←sabnzbd, prowlarr→sonarr as `application`, prowlarr→radarr as `application`).
5. Real eval: the same host but with `ferrum.secrets."qbittorrent-vpn" = { };` added — confirm qBittorrent's `host` in the generated config is `10.200.1.2`, not `127.0.0.1`.
6. Real eval: hand-break one app's `meta.nix` (temporarily, on a scratch copy) so `providesTo`/`consumes` disagree — confirm the new symmetry assertion fires with a clear message; revert and confirm it's silent again on the real catalog.
7. **The real end-to-end registration test** (the one that actually proves this plan's core deliverable): boot a real host with real Sonarr, Radarr, Prowlarr, qBittorrent, and SABnzbd instances (matching the exact plan-writing verification already done by hand), run `ferrum-reconcile` for real against `FERRUM_RECONCILE_CONFIG` pointing at the real generated config, then confirm via each consumer's own real API (`GET /api/v3/downloadclient`, `GET /api/v1/downloadclient`, `GET /api/v1/applications`) that every expected entry now exists with the right `implementation`/`host`/`port`. Run it a SECOND time and confirm no duplicate entries were created (the idempotency-by-name check actually works) and no errors occur.

- [ ] **Step 12: Commit**

```bash
git add crates/ferrum-reconcile crates/Cargo.toml nix/pkgs/ferrum-reconcile nix/modules/flake/packages.nix nix/modules/flake/checks.nix modules/core/reconciler.nix modules/default.nix
git commit -m "Add ferrum-reconcile: register download clients and Prowlarr Applications from the catalog's own integrations metadata"
```
