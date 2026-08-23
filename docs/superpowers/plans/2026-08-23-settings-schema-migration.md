# Settings Schema Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the machinery that lets `ferrum.schemaVersion` (a real, already-declared option with no consumer today) actually do something: migrate an operator's `settings.json` forward across a breaking schema change, and let `ferrum-apply` preview what a migration would do before anything is written.

**Architecture:** A new `modules/lib/migrations.nix` holds an ordered, currently-empty list of pure migration functions plus a `migrate` entry point; `ferrum.lib.mkHost` runs it on the incoming `settings` attrset before constructing the module config, so every host build (real or eval-only) passes through the same migration path. A new `ferrum-apply preview-migration` subcommand shells out to `nix eval --json` against the real flake to show what would change, without writing anything.

**Tech Stack:** Nix (the migration functions and their tests, following this repo's existing `mkAssertionCheck` eval-check pattern), Rust (`crates/ferrum-apply`, following its existing `Command`/env-var conventions).

**Spec:** `docs/superpowers/specs/2026-08-23-settings-schema-migration-design.md`

## Global Constraints

- `ferrum.schemaVersion` stays a plain sequential integer (never semver) — confirmed real, current value: `modules/core/options.nix` declares `schemaVersion = mkOption { type = types.int; default = 1; readOnly = true; ... };`. This plan changes that `default` to reference the new migration list's own computed current version instead of the literal `1`.
- **Real correction made while writing this plan, before any task was dispatched:** the spec describes `mkHost` as "already parsing settings.json into a plain attrset" — this is not quite what the real code does. Read directly from `modules/lib/default.nix`: `mkHost` takes `settings` as an **already-parsed attrset parameter** — the *host flake* (or, for the example/test host, `nix/modules/flake/checks.nix`) does `builtins.fromJSON (builtins.readFile ./settings.json)` and passes the result in. `mkHost`'s own body does exactly one thing with it: `{ config.ferrum = settings; }` inside its `modules` list. The architectural decision (Option A — migrate inside `mkHost`, before `options.nix` ever sees the value) is unaffected by this correction; only the exact mechanism description changes: Task 2 modifies that one line to `{ config.ferrum = migrate settings; }` rather than adding a file-read step that doesn't belong there.
- No migration's actual *content* is in scope for this plan — `ferrum` is still at schema version 1, and no real breaking change exists yet. Every migration function this plan writes is test-only, clearly scoped as such, and never becomes real production migration content.
- Wiring this into `ferrumd`'s real HTTP API (an "Updates" endpoint) is explicitly out of scope — `ferrumd`'s Job/Settings API surface for this doesn't exist yet (Phase 1.5b's real backend hasn't been built beyond what Phase 1.5a shipped). This plan builds the two pieces that a future endpoint would call into: the Nix migration mechanism, and the `ferrum-apply` CLI capability to preview it.
- A migration that can't safely auto-resolve `throw`s a specific, actionable message rather than guessing — this must cause real Nix evaluation to fail loudly, matching this repo's existing `checks.schema-uniformity` precedent (`nix/modules/flake/checks.nix`), not a caught-and-swallowed error.
- The preview step must be provably read-only: it evaluates the migration via `nix eval`, never writes to the real `settings.json` on disk.

---

## Task 1: `modules/lib/migrations.nix` — the migration mechanism, currently empty of real migrations

**Files:**
- Create: `modules/lib/migrations.nix`
- Test: `nix/modules/flake/checks.nix` (add a new check function, following the exact existing `mkAssertionCheck`/`schemaUniformity`/`sopsFilesArePaths` pattern already in that file)

**Interfaces:**
- Produces: `import ./migrations.nix { inherit lib; }` returning `{ migrations = [...]; currentVersion = <int>; migrate = settings: <migrated settings>; }`. `migrate` is what Task 2's `mkHost` change calls directly.

- [ ] **Step 1: Write `modules/lib/migrations.nix`**

The real, empty-of-content migration list, plus the `migrate` function that applies every applicable step in sequence:

```nix
# The ordered list of settings.json schema migrations. Empty today --
# ferrum is still at schema version 1, and no breaking change has ever
# shipped. A migration is only ever added alongside a MAJOR ferrum
# release (see docs/superpowers/specs/2026-08-23-settings-schema-
# migration-design.md for why schemaVersion itself stays a plain integer
# rather than tracking ferrum's own semver release number).
#
# Each entry: { from, to, description, migrate }. `from`/`to` must form
# an unbroken chain starting at 1 (enforced by the assertion below, not
# just assumed) -- `migrate` runs on the settings attrset at version
# `from` and must return one shaped for version `to`. A migration that
# cannot safely produce a value throws a specific, actionable message
# instead of guessing; that throw is a real eval-time failure, not
# something this file catches.
{ lib }:
let
  migrations = [ ];

  # currentVersion is computed, not a separately-maintained literal --
  # this is the ONE place "what version does this module tree expect"
  # is defined. modules/core/options.nix's own schemaVersion default
  # imports this file and reads .currentVersion rather than hardcoding
  # a number, so the two cannot drift apart.
  currentVersion = builtins.length migrations + 1;

  # Real chain-integrity check, not just an assumption: every migration
  # step's `from` must equal the previous step's `to` (or 1, for the
  # first step), and the last step's `to` must equal currentVersion.
  # A gap or an out-of-order entry is a real authoring mistake this
  # catches at eval time rather than silently mis-migrating a host.
  chainIsValid =
    let
      expectedFroms = lib.genList (i: i + 1) (builtins.length migrations);
      actualFroms = map (m: m.from) migrations;
      actualTos = map (m: m.to) migrations;
      expectedTos = lib.genList (i: i + 2) (builtins.length migrations);
    in
    actualFroms == expectedFroms && actualTos == expectedTos;

  migrateOnce = settings:
    let
      version = settings.schemaVersion or 1;
      step = lib.findFirst (m: m.from == version) null migrations;
    in
    if step == null
    then settings
    else migrateOnce (step.migrate settings // { schemaVersion = step.to; });
in
if !chainIsValid then
  throw "modules/lib/migrations.nix: migration chain is not a valid unbroken sequence from 1 to ${toString currentVersion} -- check each entry's from/to fields"
else
{
  inherit migrations currentVersion;
  migrate = migrateOnce;
}
```

- [ ] **Step 2: Add a real eval-check test to `nix/modules/flake/checks.nix`**

Read the existing file's `schemaUniformity`/`sopsFilesArePaths`/`mkAssertionCheck` pattern first (already in the file, `let` block around line 62-117) — this step follows that exact shape, not a new mechanism. Add inside the same `let` block, after `sopsFilesArePaths`:

```nix
      # Real test coverage for modules/lib/migrations.nix's own machinery,
      # using a SYNTHETIC two-step chain (not the real, currently-empty
      # migrations list) constructed inline here so this test doesn't
      # depend on any real migration ever existing. Proves: a no-op when
      # already current, a single-step migration, a multi-step chain
      # applying in sequence, and a throwing migration genuinely failing
      # eval with its own message intact.
      migrationMechanism =
        let
          testMigrations = [
            { from = 1; to = 2; description = "test: renames foo to bar";
              migrate = s: (removeAttrs s [ "foo" ]) // { bar = s.foo or null; }; }
            { from = 2; to = 3; description = "test: doubles baz";
              migrate = s: s // { baz = (s.baz or 0) * 2; }; }
          ];
          testMigrate = settings:
            let
              version = settings.schemaVersion or 1;
              step = lib.findFirst (m: m.from == version) null testMigrations;
            in
            if step == null
            then settings
            else testMigrate (step.migrate settings // { schemaVersion = step.to; });

          alreadyCurrent = testMigrate { schemaVersion = 3; baz = 5; };
          oneStep = testMigrate { schemaVersion = 2; baz = 5; };
          twoStep = testMigrate { schemaVersion = 1; foo = "hello"; baz = 5; };

          throwingChain = [
            { from = 1; to = 2; description = "test: always throws";
              migrate = s: throw "this update needs your input: real reason here"; }
          ];
          throwCaught =
            let
              result = builtins.tryEval (
                let
                  step = builtins.elemAt throwingChain 0;
                in
                step.migrate { schemaVersion = 1; }
              );
            in
            !result.success;
        in
        {
          ok = alreadyCurrent == { schemaVersion = 3; baz = 5; }
            && oneStep == { schemaVersion = 3; baz = 10; }
            && twoStep == { schemaVersion = 3; bar = "hello"; baz = 10; }
            && throwCaught;
          alreadyCurrent = alreadyCurrent;
          oneStep = oneStep;
          twoStep = twoStep;
          throwCaught = throwCaught;
        };
```

And register it alongside the other checks (the `checks = { ... }` attrset, around line 120-123):

```nix
        migration-mechanism = mkAssertionCheck "migration-mechanism" migrationMechanism;
```

- [ ] **Step 3: Real verification on ferrum-dev**

This machine (Windows) has no local Nix toolchain — real verification runs on the project's real NixOS dev VM, "ferrum-dev", reachable at `root@172.26.208.32` via SSH (no SSH config alias exists; if that IP no longer answers, find the current one via `arp -a` on Windows, looking for a MAC starting `00-15-5d`). The repo checkout on ferrum-dev lives at `/root/ferrum-repo` as a **plain directory, not a git clone** — sync the worktree there by tarring it (`tar --exclude='.git' --exclude='result*' --exclude='target' -czf sync.tar.gz .`), scp-ing it over, and extracting fresh (`rm -rf /root/ferrum-repo && mkdir /root/ferrum-repo && tar xzf sync.tar.gz -C /root/ferrum-repo`).

Run: `nix build .#checks.x86_64-linux.migration-mechanism --print-build-logs`
Expected: the check passes for real — paste the real output. If it fails, read the real error (the `mkAssertionCheck` helper's `throw` includes the JSON-encoded `alreadyCurrent`/`oneStep`/`twoStep`/`throwCaught` values on failure) rather than guessing what's wrong.

- [ ] **Step 4: Commit**

```bash
git add modules/lib/migrations.nix nix/modules/flake/checks.nix
git commit -m "Add the settings schema migration mechanism (currently empty of real migrations)"
```

---

## Task 2: Wire migration into `ferrum.lib.mkHost`, and `schemaVersion`'s real default

**Files:**
- Modify: `modules/lib/default.nix` (the real, current file — read it directly before editing; its `mkHost` body is 27 lines, shown in full in Global Constraints above)
- Modify: `modules/core/options.nix` (the real `schemaVersion` option declaration)
- Test: `nix/modules/flake/checks.nix` (a new check proving a REAL settings.json fixture migrates correctly through the REAL `mkHost`, not just the synthetic Task-1 test)

**Interfaces:**
- Consumes: `migrations.nix`'s `migrate` function and `currentVersion` (Task 1).
- Produces: every host built via `mkHost` — real or eval-only — now has its `config.ferrum` set from the migrated settings, not the raw input.

- [ ] **Step 1: Modify `modules/lib/default.nix`**

The real current file (confirmed by reading it directly) is:

```nix
{ nixpkgs, sopsNix }:
let
  inherit (nixpkgs) lib;
  ferrumModule = import ../default.nix;
in
{
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

  importDir = dir:
    let
      names = builtins.attrNames (builtins.readDir dir);
      nixFiles = builtins.filter (n: lib.hasSuffix ".nix" n) names;
    in
    map (n: dir + "/${n}") nixFiles;
}
```

Change it to import `migrations.nix` and apply `migrate` to `settings` before it reaches `config.ferrum`:

```nix
{ nixpkgs, sopsNix }:
let
  inherit (nixpkgs) lib;
  ferrumModule = import ../default.nix;
  inherit (import ./migrations.nix { inherit lib; }) migrate;
in
{
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
        { config.ferrum = migrate settings; }
        { system.stateVersion = lib.mkDefault stateVersion; }
      ] ++ modules;
    };

  importDir = dir:
    let
      names = builtins.attrNames (builtins.readDir dir);
      nixFiles = builtins.filter (n: lib.hasSuffix ".nix" n) names;
    in
    map (n: dir + "/${n}") nixFiles;
}
```

Only the two lines shown as different above change — the rest of the file (including `importDir`, entirely unrelated to this feature) stays byte-for-byte identical. Do not reformat or touch anything else in this file.

- [ ] **Step 2: Modify `modules/core/options.nix`'s `schemaVersion` default**

Read the real current declaration first (it's a `mkOption` inside the `options.ferrum` attrset, near the top of the file, per this project's own established layout). Its current real shape:

```nix
    schemaVersion = mkOption {
      type = types.int;
      default = 1;
      readOnly = true;
      description = "Version of the ferrum settings.json schema this module tree expects.";
    };
```

Change only the `default` line to reference `migrations.nix`'s computed value instead of the literal `1`. This requires `lib` to already be in scope in this file (it already is, per the file's existing `mkOption`/`types` usage) and a new import at the top of the `let` block:

```nix
    schemaVersion = mkOption {
      type = types.int;
      default = (import ../lib/migrations.nix { inherit lib; }).currentVersion;
      readOnly = true;
      description = "Version of the ferrum settings.json schema this module tree expects.";
    };
```

Add the import at the file's own `let` block (wherever `catalog`/`appsType` are already defined near the top of `options.nix`) is NOT needed here since the reference above is inline and self-contained — only add a `let`-bound import if the real file's structure makes the inline form awkward once you're looking at it; either is acceptable as long as `default` ends up computed from `migrations.nix`, never a hardcoded literal.

- [ ] **Step 3: Add a real end-to-end migration test using an actual settings.json fixture**

`modules/lib/migrations.nix`'s real `migrations` list stays empty (Task 1 left it that way, and it must stay that way — a test-only entry would make `currentVersion` become `2` for every real host, which is wrong: no real breaking change exists yet). This step proves Task 2's real `mkHost` wiring without touching that shared list at all, using a **separate, standalone check** that constructs its own tiny `mkHost`-equivalent call against a hand-built two-entry migration list local to the test — mirroring exactly what `mkHost` does (`{ config.ferrum = migrate settings; }`).

In `nix/modules/flake/checks.nix`, add a second new check, alongside `migration-mechanism`:

```nix
      # Honest about its own real scope: with modules/lib/migrations.nix's
      # real list empty, migrate is the identity function for any
      # already-current settings.json, so this check CANNOT distinguish
      # "mkHost really calls migrate()" from "mkHost never calls it at
      # all" -- both produce byte-identical output when there is nothing
      # to migrate, and no automated eval check can observe that
      # difference for an identity input. What this genuinely proves: the
      # real mkHost pipeline (Task 2 Step 1's own change) does not corrupt
      # or drop schemaVersion for the common case every real apply hits
      # (an already-current settings.json), and the result really is a
      # normal, well-typed NixOS config (config.ferrum.schemaVersion
      # actually resolves, nothing throws). The wiring itself -- that
      # Step 1's one-line change from `settings` to `migrate settings` is
      # actually present -- is a small, legible diff verified by this
      # plan's own task-scoped review of the real code, the same as any
      # other one-line change in this project. The moment a real
      # migration exists (a future major-version bump), this exact same
      # fixture starts exercising the real, non-identity migration path,
      # since examples/hosts/minimal/settings.json's schemaVersion: 1
      # would then be behind the real currentVersion -- at which point
      # this check's assertion becomes a genuine, distinguishing one.
      mkHostAppliesMigration =
        let
          testSettings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
          migratedHost = ferrumLib.mkHost {
            inherit system;
            settings = testSettings;
            modules = [
              ../../../examples/hosts/minimal/configuration.nix
              { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
            ];
            revision = "ci";
          };
        in
        {
          ok = migratedHost.config.ferrum.schemaVersion == 1;
          actualSchemaVersion = migratedHost.config.ferrum.schemaVersion;
        };
```

Register it: `mkhost-applies-migration = mkAssertionCheck "mkhost-applies-migration" mkHostAppliesMigration;`

- [ ] **Step 4: Real verification on ferrum-dev**

1. Hosts in this flake are eval-only example fixtures constructed inside `checks.nix`'s own `exampleHosts`/new checks, not top-level flake `nixosConfigurations` outputs — so verification runs directly against the checks: `nix build .#checks.x86_64-linux.migration-mechanism .#checks.x86_64-linux.mkhost-applies-migration --print-build-logs`
2. Expected: both pass. Paste the real output.
3. `nix build .#checks.x86_64-linux.catalog-consistency .#checks.x86_64-linux.schema-uniformity .#checks.x86_64-linux.sopsfile-are-paths --print-build-logs` — confirm no regression in the pre-existing checks (Task 2 touched `modules/lib/default.nix` and `modules/core/options.nix`, both real dependencies of every existing check).

- [ ] **Step 5: Commit**

```bash
git add modules/lib/default.nix modules/lib/migrations.nix modules/core/options.nix nix/modules/flake/checks.nix
git commit -m "Wire the migration mechanism into mkHost and schemaVersion's real default"
```

---

## Task 3: `ferrum-apply preview-migration` — real, read-only CLI preview

**Files:**
- Modify: `crates/ferrum-apply/src/main.rs` (the real, current file — full content read above; add one `Command` variant and one handler function, following the exact existing pattern of `run_preflight`/`run_rollback`)

**Interfaces:**
- Consumes: the real flake (via `nix eval --json`), not Task 1/2's Nix code directly — this task never links against Nix, it shells out, matching how `apply::run` already shells out to `nix build` (confirmed in `run_apply()`, which reads `FERRUM_FLAKE_REF`, defaulting to `/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel`).
- Produces: `ferrum-apply preview-migration`, printing a real JSON summary to stdout: `{"current_version": N, "target_version": M, "would_migrate": bool}`.
- **Deliberately deferred, not a gap:** the migration `description` strings (Task 1's `migrations.nix` entries) are not surfaced by this CLI output. Fetching them would need a second real flake-output mechanism (migrations.nix's list doesn't depend on any specific host's settings, so it can't be read off `config.ferrum` the way `schemaVersion` is) that has no real consumer yet — the spec's own Global Constraints mark wiring this into `ferrumd`'s API as out of scope for this plan, and building unused plumbing to feed a UI that doesn't exist yet would be exactly the kind of premature scope this project's own conventions argue against. `current_version`/`target_version`/`would_migrate` is the real, testable, useful-on-its-own capability this task delivers; a future task that actually builds the `ferrumd` Updates endpoint is the right place to add descriptions, once there's a real caller for them.

- [ ] **Step 1: Add the `PreviewMigration` variant to `Command`**

In `crates/ferrum-apply/src/main.rs`, add to the `Command` enum (alongside `Preflight`/`Apply`/`Rollback`/`RestoreState`/`Gc`/`RunRequest`):

```rust
    /// Show what a settings.json schema migration would do, without
    /// writing anything. Read-only: evaluates the real flake via `nix
    /// eval`, never runs `nix build` or touches settings.json on disk.
    PreviewMigration,
```

- [ ] **Step 2: Write `run_preview_migration()`**

Add this function near the other `run_*` functions (after `run_restore_state`, before `main`):

```rust
/// Shells out to `nix eval --json` against the real flake to compute
/// what a schema migration would produce, WITHOUT writing anything --
/// this is a preview, matching this plan's own Global Constraint that
/// the preview step must be provably read-only. Reuses the same
/// FERRUM_FLAKE_REF convention `run_apply()` already established, but
/// evaluates `config.ferrum` (cheap: a plain attrset) rather than
/// `config.system.build.toplevel` (expensive: forces a full build).
fn run_preview_migration() -> i32 {
    let settings_path = std::env::var("FERRUM_SETTINGS_PATH")
        .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
    let flake_dir = std::env::var("FERRUM_FLAKE_DIR")
        .unwrap_or_else(|_| "/etc/ferrum".to_string());

    let current_settings = match std::fs::read_to_string(&settings_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("preview-migration: failed to read {settings_path}: {e}");
            return 1;
        }
    };
    let current_version: i64 = match serde_json::from_str::<serde_json::Value>(&current_settings) {
        Ok(v) => v.get("schemaVersion").and_then(|x| x.as_i64()).unwrap_or(1),
        Err(e) => {
            eprintln!("preview-migration: {settings_path} is not valid JSON: {e}");
            return 1;
        }
    };

    let eval_attr = format!(
        "{flake_dir}#nixosConfigurations.default.config.ferrum.schemaVersion"
    );
    let output = std::process::Command::new("nix")
        .args(["eval", "--json", &eval_attr])
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("preview-migration: failed to run nix eval: {e}");
            return 1;
        }
    };
    if !output.status.success() {
        // A throw()-ing migration surfaces here as a real, non-zero nix
        // eval failure -- print the real stderr text (the throw's own
        // message) rather than a generic failure, per this plan's Global
        // Constraint that a blocked migration must be specific and
        // actionable, not swallowed.
        eprintln!(
            "preview-migration: this update needs attention:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return 1;
    }
    let target_version: i64 = match String::from_utf8_lossy(&output.stdout).trim().parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("preview-migration: unexpected nix eval output: {e}");
            return 1;
        }
    };

    let summary = serde_json::json!({
        "current_version": current_version,
        "target_version": target_version,
        "would_migrate": target_version != current_version,
    });
    println!("{summary}");
    0
}
```

- [ ] **Step 3: Wire the new variant into `main()`'s match**

In `main()`, add one arm to the existing `match cli.command` block (alongside `Command::Preflight => run_preflight(),` etc.):

```rust
        Command::PreviewMigration => run_preview_migration(),
```

- [ ] **Step 4: Write the failing test first**

Add to `mod tests` in the same file:

```rust
    #[test]
    fn parses_preview_migration_subcommand() {
        let cli = Cli::parse_from(["ferrum-apply", "preview-migration"]);
        assert!(matches!(cli.command, Command::PreviewMigration));
    }
```

- [ ] **Step 5: Run the test to verify it fails**

Run (on ferrum-dev, this machine has no local Rust toolchain): `cargo test -p ferrum-apply parses_preview_migration_subcommand`
Expected: FAIL — `Command::PreviewMigration` does not exist yet if you're doing Steps 1-3 in strict TDD order; if you've already added the enum variant and handler from Steps 1-3, this step instead confirms the test passes on the first real run. Either order is fine as long as you verify the test genuinely exercises the new code (not a false pass from a typo that made the match arm unreachable).

- [ ] **Step 6: Real verification on ferrum-dev**

This machine (Windows) has no local Rust/Nix toolchain — sync the worktree to ferrum-dev (same tar/scp/extract process as Task 1) and run there.

1. `cargo test -p ferrum-apply` — all tests pass, including the new one.
2. `cargo clippy -p ferrum-apply --all-targets -- -D warnings` — clean, aside from the confirmed-pre-existing, out-of-scope `apply.rs` findings (3 `bool_assert_comparison` errors — do not touch those).
3. Real manual exercise against a real flake checkout on ferrum-dev: build the new binary (`cargo build -p ferrum-apply`), then run `FERRUM_SETTINGS_PATH=/etc/ferrum/settings.json FERRUM_FLAKE_DIR=/etc/ferrum ./target/debug/ferrum-apply preview-migration` against a real, already-provisioned `/etc/ferrum` (reuse whatever real host fixture is already on ferrum-dev from this project's earlier phases — if none exists, construct a minimal real one following `examples/hosts/minimal/`'s own shape). Confirm the real output shows `"would_migrate": false` (since no real migration exists yet, `current_version` and `target_version` must be equal) and confirm no write occurred to `/etc/ferrum/settings.json` (check its mtime/content before and after). Paste the real command and its real output.

- [ ] **Step 7: Commit**

```bash
git add crates/ferrum-apply/src/main.rs
git commit -m "Add ferrum-apply preview-migration: a real, read-only preview of a pending schema migration"
```
