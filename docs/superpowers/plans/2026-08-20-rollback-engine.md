# Rollback Engine (Phase 1.2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and prove ferrum's rollback engine — pairing every NixOS generation switch with a btrfs snapshot of application state, so rolling back reverts the system closure and the state together, atomically. The plan's deliverable is `tests/rollback.nix` passing: upgrade a stateful test app, watch its database migrate, roll back, and see the old binary start cleanly against its pre-migration database with no data loss and no corruption.

**Architecture:** A privileged Rust CLI (`ferrum-apply`) drives the whole sequence — build, preflight, snapshot, switch, health-check — as a single systemd-invoked binary. Rollback is reboot-based: `ferrum-apply rollback` writes an intent file and reboots into the target generation; a stage-2 NixOS module (`state-restore.nix`) performs the actual btrfs subvolume swap before `@state` is mounted, using a mechanism already validated by hand against real hardware (see Phase 1.0 probes 0.2 and 0.3 in `docs/design/2026-08-19-phase-1-design.md`).

**Tech Stack:** Rust (`clap`, `serde`/`serde_json`, `anyhow`), plain `std::process::Command` for shelling out to `btrfs`/`nix-env`/`switch-to-configuration`/`systemctl` (no async runtime needed — this is a sequential CLI tool, not a server), `pkgs.rustPlatform.buildRustPackage` for Nix packaging (no crane/naersk — a single binary with no multi-crate build-cache sharing need doesn't justify the extra flake input), NixOS's `pkgs.testers.runNixOSTest` for the VM tests (same helper already used by `tests/smoke.nix`).

**Spec:** `docs/design/2026-08-19-phase-1-design.md` — particularly "Snapshot and rollback — the core of the project" and "Storage layout". This plan implements that section; where this plan and the spec disagree, the spec is the authority.

## Global Constraints

- `ferrum.storage.stateDir` defaults to `/var/lib/ferrum/state`, `ferrum.storage.snapshotDir` to `/var/lib/ferrum/snapshots` (already defined in `modules/core/options.nix`; do not hardcode these paths where the option is available).
- Apply sequence, exact order (validated end-to-end against real hardware, Phase 1.0 probes 0.2–0.5): build → preflight → stop `ferrum-apps.target` → snapshot `@state` (`btrfs subvolume snapshot -r`) → `nix-env -p /nix/var/nix/profiles/system --set <toplevel>` → `<toplevel>/bin/switch-to-configuration switch` → start `ferrum-apps.target` → health-check → classify.
- Snapshots are named `<unix_ts>-gen<N>`, never bare `genN` — generation numbers repeat after a rollback, so the timestamp prefix is load-bearing, not cosmetic.
- Rollback uses `nix-env -p /nix/var/nix/profiles/system --switch-generation <N>` (arbitrary N), never `--rollback` (which only steps back one generation), followed by `switch-to-configuration boot` (never `switch` — that would activate the old closure against still-current state), then a real `reboot`.
- The boot-time state restore runs as a stage-2 systemd unit with `unitConfig.DefaultDependencies = false`, `after = [ "local-fs-pre.target" ]`, `before = [ "<state-mount-unit>" "local-fs.target" ]`, `wantedBy = [ "local-fs.target" ]` — this exact shape was validated by hand (probe 0.3): the unit's `ActiveEnterTimestamp` measured a full second before the mount unit's.
- The btrfs swap mechanism, exact validated sequence (probe 0.2): mount the top-level volume (`subvolid=5`) at a scratch path, `btrfs subvolume snapshot` the chosen read-only snapshot into a writable copy, `mv` the live `@state` subvolume to `trash/@state.replaced.<ts>`, `mv` the writable copy into `@state`'s place, unmount the scratch mount. Both renames are on the same top-level volume (required for an atomic rename) and succeeded with no `EBUSY` when `@state` was not yet mounted elsewhere.
- A restore failure must never fail the boot: `ferrum-apply restore-state` always exits 0. Failure is signaled by writing `/run/ferrum/state-restore-failed`, which a `ConditionPathExists` on `ferrum-apps.target` uses to hold managed apps down rather than start them against possibly-inconsistent state.
- `/etc/ferrum/custom/` and all Nix module option types stay JSON-expressible — this plan adds no options of type `path`/`package`/function (there's nothing in this plan that needs a new `ferrum.*` option at all; `ferrum-apply` reads paths from `ferrum.storage.*`, already defined).
- Out of scope for this plan (deferred to a follow-up): `ferrum-apply gc` and generation retention, the unmanaged-switch marker/warning, `ferrum.apply.autoRollbackOnFailure`. Scoping this plan to build+snapshot+switch+rollback+restore keeps it to one coherent, independently-testable deliverable, per the writing-plans skill's scope-check guidance. GC and the unmanaged-switch warning are safety/polish features that don't block proving the core mechanism works.

---

## File Structure

```
nix/pkgs/testapp/
  Cargo.toml           # standalone binary, NOT part of the crates/ workspace (pure test fixture)
  src/main.rs
  default.nix           # buildRustPackage wrapper
crates/
  Cargo.toml            # workspace root, currently one member
  ferrum-apply/
    Cargo.toml
    src/
      main.rs            # CLI entry point (clap)
      preflight.rs        # Task 3
      apply.rs            # Task 4 (build, snapshot, switch, health-check, classify)
      journal.rs           # Task 4 (JournalEntry type + read/write) -- shared by apply, list-generations, restore-state
      generations.rs        # Task 5 (list-generations: parse `nix-env --list-generations`, correlate with journal)
      restore_state.rs       # Task 6
      rollback.rs             # Task 7
nix/pkgs/ferrum-apply/
  default.nix             # buildRustPackage wrapper for the crates/ferrum-apply binary
modules/core/
  state-restore.nix        # Task 6 -- the boot-time NixOS module
tests/
  rollback.nix               # Task 8
  rollback-proves-necessity.nix  # Task 8
nix/modules/flake/
  checks.nix                  # extended: cargo test, clippy, tests/rollback.nix, tests/rollback-proves-necessity.nix
  packages.nix                  # extended: testapp, ferrum-apply
  devshells.nix                   # extended: rust toolchain
```

`ferrum-apply` is one crate, not split further — its five subcommands (`preflight`, `apply`, `rollback`, `restore-state`, `gc`) share the `JournalEntry` type and all operate on the same `ferrum.storage.*` paths; splitting them into separate crates would just add inter-crate plumbing for no isolation benefit. Internal modules (`preflight.rs`, `apply.rs`, etc.) keep each subcommand's logic in its own file so no single file grows past a few hundred lines.

`testapp` stays outside the `crates/` workspace and outside the `ferrum.apps.*` catalog: it is a test fixture, not a product component, and pretending it's a catalog app (with a `meta.nix`/`service.nix` pair) would misrepresent it to `checks.catalog-consistency`. Its systemd service is defined inline in `tests/rollback.nix`'s VM node config instead.

---

### Task 1: `ferrum-testapp` — the two-behavior test binary

**Files:**
- Create: `nix/pkgs/testapp/Cargo.toml`
- Create: `nix/pkgs/testapp/src/main.rs`
- Create: `nix/pkgs/testapp/default.nix`
- Modify: `nix/modules/flake/packages.nix` (add the `testapp` package)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a binary `ferrum-testapp` accepting `--app-version <1|2>`, `--db-path <path>` (default `/var/lib/ferrum-testapp/app.db`), `--listen <addr:port>` (default `127.0.0.1:8099`). HTTP API: `GET /ping` → `200 OK`; `GET /rows` → JSON array of `{"id": <int>, "text": <string>}` objects (preserving each note's row id is more useful than bare strings, and every consumer in this plan only substring-matches the response, so the richer shape costs nothing); `POST /notes` with body `{"text": "..."}` → inserts a row, `204 No Content`. On startup: opens (creating if absent) a SQLite database at `--db-path`, reads `PRAGMA user_version`. If `--app-version 1` and `user_version > 1`, prints `FATAL: database schema version {v} is newer than this binary supports` to stderr and exits with code 1 *before* starting the HTTP server. Otherwise creates the `notes` table if absent and sets `user_version` to the app version (1 or 2) if it's currently lower. If `--app-version 2`, additionally ensures a `migrated_at TEXT` column exists on `notes` (added via `ALTER TABLE` the first time `user_version` moves from 1 to 2 — this is the "migration" the rollback test exists to catch a downgrade against).
- Produces (Nix): `packages.ferrum-testapp` (the binary), consumed by Task 8's `tests/rollback.nix`.

- [ ] **Step 1: Write the Cargo manifest**

```toml
# nix/pkgs/testapp/Cargo.toml
[package]
name = "ferrum-testapp"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "ferrum-testapp"
path = "src/main.rs"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
rusqlite = { version = "0.31", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
```

- [ ] **Step 2: Write the failing test — schema-version refusal**

```rust
// nix/pkgs/testapp/src/main.rs (top of file, test module at the bottom)
#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn v1_refuses_a_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("app.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("PRAGMA user_version = 2;").unwrap();
        }
        let err = check_schema_version(&db_path, 1).unwrap_err();
        assert!(err.to_string().contains("newer than this binary supports"));
    }

    #[test]
    fn v1_accepts_a_fresh_database() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("app.db");
        check_schema_version(&db_path, 1).unwrap();
        let conn = Connection::open(&db_path).unwrap();
        let uv: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(uv, 1);
    }

    #[test]
    fn v2_migrates_a_v1_database_and_adds_migrated_at() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("app.db");
        check_schema_version(&db_path, 1).unwrap(); // simulate a prior v1 install
        check_schema_version(&db_path, 2).unwrap();
        let conn = Connection::open(&db_path).unwrap();
        let uv: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(uv, 2);
        // ALTER TABLE succeeding (not erroring on a duplicate column) proves
        // the migration path is idempotent across repeated v2 starts.
        check_schema_version(&db_path, 2).unwrap();
    }
}
```

Add `tempfile = "3"` under `[dev-dependencies]` in the Cargo manifest for this test.

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd nix/pkgs/testapp && cargo test`
Expected: FAIL to compile — `check_schema_version` is not defined yet.

- [ ] **Step 4: Implement `check_schema_version` and the rest of `main.rs`**

```rust
// nix/pkgs/testapp/src/main.rs
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    app_version: u32,
    #[arg(long, default_value = "/var/lib/ferrum-testapp/app.db")]
    db_path: String,
    #[arg(long, default_value = "127.0.0.1:8099")]
    listen: String,
}

/// Opens (creating if absent) the database at `db_path` and reconciles its
/// `user_version` against `app_version`. Returns an error -- never panics --
/// when `app_version` is older than the database's recorded schema version,
/// mirroring how a real app (e.g. Sonarr) refuses to start against a
/// database a newer release already migrated.
fn check_schema_version(db_path: &Path, app_version: u32) -> anyhow::Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_path)?;
    let current: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;

    if current > app_version {
        anyhow::bail!(
            "FATAL: database schema version {current} is newer than this binary supports"
        );
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL
        );",
    )?;

    if app_version >= 2 {
        let has_migrated_at: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('notes') WHERE name = 'migrated_at'")?
            .exists([])?;
        if !has_migrated_at {
            conn.execute_batch("ALTER TABLE notes ADD COLUMN migrated_at TEXT;")?;
        }
    }

    if current < app_version {
        conn.execute_batch(&format!("PRAGMA user_version = {app_version};"))?;
    }

    Ok(conn)
}

#[derive(Deserialize)]
struct NewNote {
    text: String,
}

#[derive(Serialize)]
struct Note {
    id: i64,
    text: String,
}

type SharedConn = Arc<Mutex<Connection>>;

async fn ping() -> StatusCode {
    StatusCode::OK
}

async fn list_notes(State(conn): State<SharedConn>) -> Json<Vec<Note>> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, text FROM notes ORDER BY id").unwrap();
    let notes = stmt
        .query_map([], |row| {
            Ok(Note {
                id: row.get(0)?,
                text: row.get(1)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    Json(notes)
}

async fn add_note(State(conn): State<SharedConn>, Json(new_note): Json<NewNote>) -> StatusCode {
    let conn = conn.lock().unwrap();
    conn.execute("INSERT INTO notes (text) VALUES (?1)", [new_note.text])
        .unwrap();
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let conn = match check_schema_version(Path::new(&args.db_path), args.app_version) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let shared: SharedConn = Arc::new(Mutex::new(conn));

    let app = Router::new()
        .route("/ping", get(ping))
        .route("/rows", get(list_notes))
        .route("/notes", post(add_note))
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd nix/pkgs/testapp && cargo test`
Expected: PASS (3 tests: `v1_refuses_a_newer_schema`, `v1_accepts_a_fresh_database`, `v2_migrates_a_v1_database_and_adds_migrated_at`)

- [ ] **Step 6: Package it with Nix**

```nix
# nix/pkgs/testapp/default.nix
{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "ferrum-testapp";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;
}
```

Run `cd nix/pkgs/testapp && cargo generate-lockfile` to produce `Cargo.lock` before this builds.

- [ ] **Step 7: Wire it into the flake's packages**

Read `nix/modules/flake/packages.nix` first (`get_symbols_overview` per this project's CLAUDE.md) to see the existing `perSystem` shape, then add:

```nix
# inside the existing `packages = { ... };` attrset in nix/modules/flake/packages.nix
ferrum-testapp = pkgs.callPackage ../../../nix/pkgs/testapp { };
```

- [ ] **Step 8: Verify the Nix package builds**

Run: `nix build .#ferrum-testapp --print-build-logs`
Expected: builds successfully, `./result/bin/ferrum-testapp --help` runs.

- [ ] **Step 9: Commit**

```bash
git add nix/pkgs/testapp nix/modules/flake/packages.nix
git commit -m "Add ferrum-testapp: the two-behavior fixture for the rollback test"
```

---

### Task 2: `crates/` workspace + `ferrum-apply` CLI scaffold

**Files:**
- Create: `crates/Cargo.toml`
- Create: `crates/ferrum-apply/Cargo.toml`
- Create: `crates/ferrum-apply/src/main.rs`
- Create: `nix/pkgs/ferrum-apply/default.nix`
- Modify: `nix/modules/flake/packages.nix` (add `ferrum-apply`)
- Modify: `nix/modules/flake/devshells.nix` (add the Rust toolchain)
- Modify: `nix/modules/flake/checks.nix` (add `cargo test` and `cargo clippy` checks)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: a `Command` enum (`Preflight`, `Apply`, `Rollback { to: u32 }`, `RestoreState`, `Gc`) that Tasks 3–7 match on and implement. `main()`'s `match cli.command` handles each variant inline (not via a `main.rs`-local `run_<name>()` wrapper — Tasks 3–7 each replace their own arm's body directly, calling into their own module's `run()` function, e.g. `preflight::run(...)`, exactly as those tasks' own Steps show); this task's arms are real, compiling, minimal implementations printing `"not yet implemented"` and returning exit code `1` — that's the actual, current, correct behavior of an unbuilt subcommand, not a plan placeholder (every subsequent task replaces exactly one arm's body with its real behavior and its own test).

- [ ] **Step 1: Write the workspace root**

```toml
# crates/Cargo.toml
[workspace]
resolver = "2"
members = ["ferrum-apply"]
```

- [ ] **Step 2: Write the failing test — CLI parsing**

```rust
// crates/ferrum-apply/src/main.rs (test module)
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_preflight() {
        let cli = Cli::parse_from(["ferrum-apply", "preflight"]);
        assert!(matches!(cli.command, Command::Preflight));
    }

    #[test]
    fn parses_rollback_with_target_generation() {
        let cli = Cli::parse_from(["ferrum-apply", "rollback", "--to", "42"]);
        match cli.command {
            Command::Rollback { to } => assert_eq!(to, 42),
            other => panic!("expected Rollback, got {other:?}"),
        }
    }

    #[test]
    fn parses_all_five_subcommands() {
        for args in [
            vec!["ferrum-apply", "preflight"],
            vec!["ferrum-apply", "apply"],
            vec!["ferrum-apply", "rollback", "--to", "1"],
            vec!["ferrum-apply", "restore-state"],
            vec!["ferrum-apply", "gc"],
        ] {
            Cli::try_parse_from(args).expect("all five subcommands must parse");
        }
    }
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd crates && cargo test -p ferrum-apply`
Expected: FAIL to compile — `Cli`/`Command` not defined.

- [ ] **Step 4: Write the crate manifest and CLI scaffold**

```toml
# crates/ferrum-apply/Cargo.toml
[package]
name = "ferrum-apply"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "ferrum-apply"
path = "src/main.rs"

[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"

[dev-dependencies]
tempfile = "3"
```

```rust
// crates/ferrum-apply/src/main.rs
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ferrum-apply")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Check free space and that the snapshot directory is a real subvolume.
    Preflight,
    /// Build, snapshot state, switch, health-check, classify.
    Apply,
    /// Schedule a reboot into an earlier generation with its matching state.
    Rollback {
        #[arg(long)]
        to: u32,
    },
    /// Run at boot: perform a pending state restore, if one is scheduled.
    RestoreState,
    /// Prune old generations and their snapshots together.
    Gc,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Preflight => {
            eprintln!("preflight: not yet implemented");
            1
        }
        Command::Apply => {
            eprintln!("apply: not yet implemented");
            1
        }
        Command::Rollback { to: _ } => {
            eprintln!("rollback: not yet implemented");
            1
        }
        Command::RestoreState => {
            eprintln!("restore-state: not yet implemented");
            1
        }
        Command::Gc => {
            eprintln!("gc: not yet implemented");
            1
        }
    };
    std::process::exit(exit_code);
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd crates && cargo test -p ferrum-apply`
Expected: PASS (3 tests)

- [ ] **Step 6: Package it with Nix**

```nix
# nix/pkgs/ferrum-apply/default.nix
{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "ferrum-apply";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-apply";
}
```

Run `cd crates && cargo generate-lockfile` to produce `Cargo.lock`.

- [ ] **Step 7: Wire it into the flake's packages, devshell, and checks**

In `nix/modules/flake/packages.nix`, add:

```nix
ferrum-apply = pkgs.callPackage ../../../nix/pkgs/ferrum-apply { };
```

In `nix/modules/flake/devshells.nix`, add `pkgs.cargo pkgs.rustc pkgs.clippy pkgs.rustfmt` to the existing `packages` list.

In `nix/modules/flake/checks.nix`, add two checks alongside the existing ones (`catalog-consistency`, `schema-uniformity`, etc.):

```nix
cargo-test-ferrum-apply = pkgs.runCommand "ferrum-check-cargo-test-ferrum-apply"
  {
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc ];
  }
  ''
    cp -r ${../../../crates} crates
    chmod -R u+w crates
    cd crates
    cargo test -p ferrum-apply --offline || cargo test -p ferrum-apply
    touch $out
  '';

clippy-ferrum-apply = pkgs.runCommand "ferrum-check-clippy-ferrum-apply"
  {
    nativeBuildInputs = [ pkgs.cargo pkgs.rustc pkgs.clippy ];
  }
  ''
    cp -r ${../../../crates} crates
    chmod -R u+w crates
    cd crates
    cargo clippy -p ferrum-apply -- -D warnings
    touch $out
  '';
```

- [ ] **Step 8: Verify the Nix package and checks build**

Run: `nix build .#ferrum-apply --print-build-logs`
Expected: builds, `./result/bin/ferrum-apply --help` lists all five subcommands.

Run: `nix build .#checks.x86_64-linux.cargo-test-ferrum-apply .#checks.x86_64-linux.clippy-ferrum-apply --print-build-logs`
Expected: both pass.

- [ ] **Step 9: Commit**

```bash
git add crates nix/pkgs/ferrum-apply nix/modules/flake/packages.nix nix/modules/flake/devshells.nix nix/modules/flake/checks.nix
git commit -m "Scaffold the ferrum-apply crate: CLI parsing for all five subcommands"
```

---

### Task 3: `ferrum-apply preflight`

**Files:**
- Create: `crates/ferrum-apply/src/preflight.rs`
- Modify: `crates/ferrum-apply/src/main.rs` (wire the `Preflight` arm to `preflight::run`)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first subcommand implemented).
- Produces: `preflight::run(state_dir: &Path, snapshot_dir: &Path, min_free_gib: u64) -> anyhow::Result<()>` — returns `Ok(())` if all checks pass, `Err` with a human-readable reason otherwise. `main.rs` calls this with paths read from environment variables `FERRUM_STATE_DIR` and `FERRUM_SNAPSHOT_DIR` (set by the systemd unit from `ferrum.storage.stateDir`/`ferrum.storage.snapshotDir` — wiring the actual environment variables into the unit is Task 6's job, since that's where the systemd unit itself is defined; this task's `run` function takes them as plain arguments so it's testable without any systemd involvement) and `FERRUM_MIN_FREE_GIB` (default `10` if unset, matching `ferrum.storage.minFreeGiB`'s default in `modules/core/options.nix`).
- Produces (for Task 4): `preflight::check_free_space(path: &Path, min_gib: u64) -> anyhow::Result<()>`, `preflight::check_is_subvolume(path: &Path) -> anyhow::Result<()>` — Task 4's `apply` calls these directly before doing anything destructive.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/ferrum-apply/src/preflight.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_check_passes_when_plenty_free() {
        let dir = tempfile::tempdir().unwrap();
        // The temp dir's filesystem almost certainly has at least 1 MiB free.
        check_free_space(dir.path(), 0).unwrap();
    }

    #[test]
    fn free_space_check_fails_when_requirement_is_absurd() {
        let dir = tempfile::tempdir().unwrap();
        // No real filesystem has an exbibyte free.
        let err = check_free_space(dir.path(), 1_000_000_000).unwrap_err();
        assert!(err.to_string().contains("free space"));
    }

    #[test]
    fn is_subvolume_check_fails_on_a_plain_directory() {
        let dir = tempfile::tempdir().unwrap();
        // A plain tempdir is never a btrfs subvolume.
        let err = check_is_subvolume(dir.path()).unwrap_err();
        assert!(err.to_string().contains("not a btrfs subvolume"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd crates && cargo test -p ferrum-apply preflight`
Expected: FAIL to compile — functions not defined.

- [ ] **Step 3: Implement `preflight.rs`**

```rust
// crates/ferrum-apply/src/preflight.rs
use std::path::Path;

pub fn check_free_space(path: &Path, min_gib: u64) -> anyhow::Result<()> {
    let stat = rustix::fs::statvfs(path)?;
    let free_bytes = stat.f_bavail as u64 * stat.f_frsize as u64;
    let free_gib = free_bytes / (1024 * 1024 * 1024);
    if free_gib < min_gib {
        anyhow::bail!(
            "not enough free space at {}: {free_gib} GiB free, {min_gib} GiB required",
            path.display()
        );
    }
    Ok(())
}

pub fn check_is_subvolume(path: &Path) -> anyhow::Result<()> {
    let output = std::process::Command::new("btrfs")
        .args(["subvolume", "show"])
        .arg(path)
        .output()?;
    if !output.status.success() {
        anyhow::bail!(
            "{} is not a btrfs subvolume: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn run(state_dir: &Path, snapshot_dir: &Path, min_free_gib: u64) -> anyhow::Result<()> {
    check_free_space(state_dir, min_free_gib)?;
    check_is_subvolume(state_dir)?;
    check_is_subvolume(snapshot_dir)?;
    Ok(())
}
```

Add `rustix = { version = "0.38", features = ["fs"] }` to `crates/ferrum-apply/Cargo.toml`'s `[dependencies]`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd crates && cargo test -p ferrum-apply preflight`
Expected: PASS (3 tests)

- [ ] **Step 5: Wire the `Preflight` command to call it**

```rust
// crates/ferrum-apply/src/main.rs -- replace the Command::Preflight arm
mod preflight;

// ...inside main(), replace:
Command::Preflight => {
    let state_dir = std::env::var("FERRUM_STATE_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/state".to_string());
    let snapshot_dir = std::env::var("FERRUM_SNAPSHOT_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/snapshots".to_string());
    let min_free_gib: u64 = std::env::var("FERRUM_MIN_FREE_GIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    match preflight::run(
        std::path::Path::new(&state_dir),
        std::path::Path::new(&snapshot_dir),
        min_free_gib,
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("preflight failed: {e}");
            1
        }
    }
}
```

- [ ] **Step 6: Run the full test suite**

Run: `cd crates && cargo test -p ferrum-apply`
Expected: PASS (all tests from Tasks 2 and 3)

- [ ] **Step 7: Commit**

```bash
git add crates/ferrum-apply/src/preflight.rs crates/ferrum-apply/src/main.rs crates/ferrum-apply/Cargo.toml
git commit -m "Implement ferrum-apply preflight: free space and subvolume checks"
```

---

### Task 4: `ferrum-apply apply` — build, snapshot, switch, health-check, classify

**Files:**
- Create: `crates/ferrum-apply/src/journal.rs`
- Create: `crates/ferrum-apply/src/apply.rs`
- Modify: `crates/ferrum-apply/src/main.rs` (wire the `Apply` arm)

**Interfaces:**
- Consumes: `preflight::run` (Task 3).
- Produces: `journal::JournalEntry { snapshot: String, generation: u32, toplevel: String, taken_at: String, quiesced: bool }` (derives `Serialize`, `Deserialize`, `Debug`, `Clone`) — the on-disk journal format at `{journal_dir}/{snapshot}.json`. Produces `journal::write(journal_dir: &Path, entry: &JournalEntry) -> anyhow::Result<()>` and `journal::read(journal_dir: &Path, snapshot: &str) -> anyhow::Result<JournalEntry>`, both consumed by Task 5 (`list-generations`) and Task 6 (`restore-state`). Produces `apply::ApplyResult` enum (`Succeeded`, `Degraded(String)`, `Failed(String)`) and `apply::run(flake_ref: &str, storage: &StorageConfig) -> anyhow::Result<ApplyResult>`.

- [ ] **Step 1: Write the failing tests for the journal**

```rust
// crates/ferrum-apply/src/journal.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let entry = JournalEntry {
            snapshot: "1770000000-gen42".to_string(),
            generation: 42,
            toplevel: "/nix/store/abc-nixos-system-test".to_string(),
            taken_at: "2026-08-20T00:00:00Z".to_string(),
            quiesced: true,
        };
        write(dir.path(), &entry).unwrap();
        let read_back = read(dir.path(), "1770000000-gen42").unwrap();
        assert_eq!(read_back.generation, 42);
        assert_eq!(read_back.toplevel, "/nix/store/abc-nixos-system-test");
        assert!(read_back.quiesced);
    }

    #[test]
    fn reading_a_missing_entry_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path(), "does-not-exist").is_err());
    }

    #[test]
    fn snapshot_name_embeds_timestamp_and_generation() {
        let name = snapshot_name(1770000000, 42);
        assert_eq!(name, "1770000000-gen42");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd crates && cargo test -p ferrum-apply journal`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `journal.rs`**

```rust
// crates/ferrum-apply/src/journal.rs
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JournalEntry {
    pub snapshot: String,
    pub generation: u32,
    pub toplevel: String,
    pub taken_at: String,
    pub quiesced: bool,
}

pub fn snapshot_name(unix_ts: u64, generation: u32) -> String {
    format!("{unix_ts}-gen{generation}")
}

pub fn write(journal_dir: &Path, entry: &JournalEntry) -> anyhow::Result<()> {
    std::fs::create_dir_all(journal_dir)?;
    let path = journal_dir.join(format!("{}.json", entry.snapshot));
    let tmp_path = journal_dir.join(format!("{}.json.tmp", entry.snapshot));
    std::fs::write(&tmp_path, serde_json::to_string_pretty(entry)?)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

pub fn read(journal_dir: &Path, snapshot: &str) -> anyhow::Result<JournalEntry> {
    let path = journal_dir.join(format!("{snapshot}.json"));
    let content = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("no journal entry for {snapshot}: {e}"))?;
    Ok(serde_json::from_str(&content)?)
}

pub fn list(journal_dir: &Path) -> anyhow::Result<Vec<JournalEntry>> {
    if !journal_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for f in std::fs::read_dir(journal_dir)? {
        let f = f?;
        if f.path().extension().and_then(|e| e.to_str()) == Some("json") {
            let content = std::fs::read_to_string(f.path())?;
            entries.push(serde_json::from_str(&content)?);
        }
    }
    Ok(entries)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd crates && cargo test -p ferrum-apply journal`
Expected: PASS (3 tests)

- [ ] **Step 5: Write the failing test for apply's exit-code classification**

Classification is the one piece of `apply` that's pure and testable without a real system (the rest — actually building, snapshotting, switching — is integration-level, verified by Task 8's VM test).

```rust
// crates/ferrum-apply/src/apply.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_0_with_all_units_active_is_succeeded() {
        assert_eq!(
            classify(0, true),
            ApplyResult::Succeeded
        );
    }

    #[test]
    fn exit_0_with_a_unit_down_is_degraded() {
        assert_eq!(
            classify(0, false),
            ApplyResult::Degraded("one or more managed units failed to become active".to_string())
        );
    }

    #[test]
    fn exit_2_is_degraded_activation() {
        assert_eq!(
            classify(2, true),
            ApplyResult::Degraded("activation script failed (exit 2)".to_string())
        );
    }

    #[test]
    fn exit_4_is_degraded_units() {
        assert_eq!(
            classify(4, true),
            ApplyResult::Degraded("one or more units failed to start or restart (exit 4)".to_string())
        );
    }
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd crates && cargo test -p ferrum-apply apply`
Expected: FAIL to compile.

- [ ] **Step 7: Implement `apply.rs`**

```rust
// crates/ferrum-apply/src/apply.rs
use crate::journal::{self, JournalEntry};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq)]
pub enum ApplyResult {
    Succeeded,
    Degraded(String),
    Failed(String),
}

/// Turns switch-to-configuration's exit code plus a post-switch health
/// summary into a classification. See Global Constraints in the plan for
/// what each exit code means: 0 = ok, 2 = activation script failed,
/// 4 = one or more units failed to start/restart.
fn classify(switch_exit_code: i32, all_units_active: bool) -> ApplyResult {
    match switch_exit_code {
        0 if all_units_active => ApplyResult::Succeeded,
        0 => ApplyResult::Degraded(
            "one or more managed units failed to become active".to_string(),
        ),
        2 => ApplyResult::Degraded("activation script failed (exit 2)".to_string()),
        4 => ApplyResult::Degraded(
            "one or more units failed to start or restart (exit 4)".to_string(),
        ),
        other => ApplyResult::Degraded(format!("switch-to-configuration exited {other}")),
    }
}

fn run_ok(cmd: &mut Command) -> anyhow::Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("command failed: {cmd:?}");
    }
    Ok(())
}

fn current_generation() -> anyhow::Result<u32> {
    let target = std::fs::read_link("/nix/var/nix/profiles/system")?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("unexpected profile link target: {target:?}"))?;
    // profile links look like "system-<N>-link"
    let n: u32 = name
        .strip_prefix("system-")
        .and_then(|s| s.strip_suffix("-link"))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("could not parse generation number from {name}"))?;
    Ok(n)
}

fn all_managed_units_active() -> anyhow::Result<bool> {
    let output = Command::new("systemctl")
        .args(["is-active", "ferrum-apps.target"])
        .output()?;
    Ok(output.status.success())
}

pub struct StorageConfig {
    pub state_dir: std::path::PathBuf,
    pub snapshot_dir: std::path::PathBuf,
    pub journal_dir: std::path::PathBuf,
    pub min_free_gib: u64,
}

pub fn run(flake_ref: &str, storage: &StorageConfig) -> anyhow::Result<ApplyResult> {
    // 1. Build (apps still running -- the slow part).
    let build_output = Command::new("nix")
        .args(["build", "--no-link", "--print-out-paths", flake_ref])
        .output()?;
    if !build_output.status.success() {
        return Ok(ApplyResult::Failed(format!(
            "nix build failed: {}",
            String::from_utf8_lossy(&build_output.stderr)
        )));
    }
    let toplevel = String::from_utf8(build_output.stdout)?.trim().to_string();

    let current = current_generation()?;
    if Path::new(&toplevel) == std::fs::read_link("/run/current-system")? {
        return Ok(ApplyResult::Succeeded); // nothing changed
    }

    // 2. Preflight, before touching anything.
    crate::preflight::run(&storage.state_dir, &storage.snapshot_dir, storage.min_free_gib)
        .map_err(|e| anyhow::anyhow!("preflight failed, nothing changed: {e}"))?;

    let generation = current;

    // 3. Stop managed apps -- downtime starts here.
    run_ok(Command::new("systemctl").args(["stop", "ferrum-apps.target"]))?;

    // 4. Snapshot @state.
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let snapshot_name = journal::snapshot_name(ts, generation);
    let snapshot_path = storage.snapshot_dir.join(&snapshot_name);
    run_ok(
        Command::new("btrfs")
            .args(["subvolume", "snapshot", "-r"])
            .arg(&storage.state_dir)
            .arg(&snapshot_path),
    )?;

    let entry = JournalEntry {
        snapshot: snapshot_name.clone(),
        generation,
        toplevel: toplevel.clone(),
        taken_at: chrono_taken_at(),
        quiesced: true,
    };
    journal::write(&storage.journal_dir, &entry)?;

    // 5. Set the profile to the new generation.
    run_ok(
        Command::new("nix-env")
            .args(["-p", "/nix/var/nix/profiles/system", "--set"])
            .arg(&toplevel),
    )?;

    // 6. Activate.
    let switch_status = Command::new(format!("{toplevel}/bin/switch-to-configuration"))
        .arg("switch")
        .status()?;
    let switch_exit_code = switch_status.code().unwrap_or(-1);

    // 7. Restart managed apps -- REQUIRED: switch-to-configuration only
    // restarts units whose closure changed, so anything we stopped in step 3
    // that DIDN'T change would otherwise stay down.
    run_ok(Command::new("systemctl").args(["start", "ferrum-apps.target"]))?;

    let healthy = all_managed_units_active()?;
    Ok(classify(switch_exit_code, healthy))
}

fn chrono_taken_at() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // A minimal RFC3339-ish timestamp without pulling in the `chrono` crate
    // for one call site; precision to the second is enough for a journal.
    format!("{}", now.as_secs())
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `cd crates && cargo test -p ferrum-apply apply`
Expected: PASS (4 classification tests)

- [ ] **Step 9: Wire the `Apply` command to call it**

```rust
// crates/ferrum-apply/src/main.rs
mod apply;
mod journal;

// replace the Command::Apply arm:
Command::Apply => {
    let storage = apply::StorageConfig {
        state_dir: std::env::var("FERRUM_STATE_DIR")
            .unwrap_or_else(|_| "/var/lib/ferrum/state".to_string())
            .into(),
        snapshot_dir: std::env::var("FERRUM_SNAPSHOT_DIR")
            .unwrap_or_else(|_| "/var/lib/ferrum/snapshots".to_string())
            .into(),
        journal_dir: std::env::var("FERRUM_JOURNAL_DIR")
            .unwrap_or_else(|_| "/var/lib/ferrum/journal".to_string())
            .into(),
        min_free_gib: std::env::var("FERRUM_MIN_FREE_GIB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10),
    };
    let flake_ref = std::env::var("FERRUM_FLAKE_REF")
        .unwrap_or_else(|_| "/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel".to_string());
    match apply::run(&flake_ref, &storage) {
        Ok(apply::ApplyResult::Succeeded) => 0,
        Ok(apply::ApplyResult::Degraded(reason)) => {
            eprintln!("apply degraded: {reason}");
            0 // the switch itself succeeded; degraded is reported, not a process failure
        }
        Ok(apply::ApplyResult::Failed(reason)) => {
            eprintln!("apply failed: {reason}");
            1
        }
        Err(e) => {
            eprintln!("apply error: {e}");
            1
        }
    }
}
```

- [ ] **Step 10: Run the full test suite**

Run: `cd crates && cargo test -p ferrum-apply`
Expected: PASS (all tests from Tasks 2, 3, and 4)

- [ ] **Step 11: Commit**

```bash
git add crates/ferrum-apply/src/journal.rs crates/ferrum-apply/src/apply.rs crates/ferrum-apply/src/main.rs
git commit -m "Implement ferrum-apply apply: build, snapshot, switch, classify"
```

---

### Task 5: `ferrum-apply list-generations` groundwork (journal + generation parsing)

Note: there is no separate `list-generations` CLI subcommand in this plan's scope (that's a `ferrumd` API concern, Phase 1.5) — this task builds the parsing Task 6 and Task 7 both need: correlating `nix-env --list-generations` output with journal entries so `restore-state` and `rollback` can validate a target generation actually has a snapshot before acting on it.

**Files:**
- Create: `crates/ferrum-apply/src/generations.rs`
- Modify: `crates/ferrum-apply/src/main.rs` (declare the module)

**Interfaces:**
- Consumes: `journal::list`, `journal::JournalEntry` (Task 4).
- Produces: `generations::GenerationInfo { generation: u32, date: String, current: bool, snapshot: Option<JournalEntry> }`. Produces `generations::parse_nix_env_list(output: &str) -> Vec<(u32, String, bool)>` (generation, date string, is-current). Produces `generations::correlate(generations: Vec<(u32, String, bool)>, journal_entries: Vec<JournalEntry>) -> Vec<GenerationInfo>` — for each generation, finds the *latest* journal entry whose `generation` field matches (there can be more than one, if a generation number was reused after a rollback; "latest" is determined by comparing the `<ts>` prefix of `snapshot`, not by parse order). Produces `generations::is_rollbackable(info: &GenerationInfo) -> Result<(), String>` — `Err` with a human-readable reason if the generation has no snapshot, consumed by Task 7's `rollback` to refuse before writing an intent file.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/ferrum-apply/src/generations.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalEntry;

    const SAMPLE_OUTPUT: &str = "\
   1   2026-08-19 23:37:29   
   2   2026-08-19 23:58:13   
   3   2026-08-20 00:02:36   (current)
";

    #[test]
    fn parses_nix_env_list_generations_output() {
        let parsed = parse_nix_env_list(SAMPLE_OUTPUT);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], (1, "2026-08-19 23:37:29".to_string(), false));
        assert_eq!(parsed[2], (3, "2026-08-20 00:02:36".to_string(), true));
    }

    fn entry(snapshot: &str, generation: u32) -> JournalEntry {
        JournalEntry {
            snapshot: snapshot.to_string(),
            generation,
            toplevel: "/nix/store/x".to_string(),
            taken_at: "2026-08-20T00:00:00Z".to_string(),
            quiesced: true,
        }
    }

    #[test]
    fn correlates_the_latest_snapshot_when_a_generation_number_repeats() {
        let generations = vec![(1, "d1".to_string(), false)];
        let journal_entries = vec![
            entry("1000-gen1", 1),
            entry("2000-gen1", 1), // a later snapshot for the same generation number
        ];
        let infos = correlate(generations, journal_entries);
        assert_eq!(infos[0].snapshot.as_ref().unwrap().snapshot, "2000-gen1");
    }

    #[test]
    fn generation_with_no_snapshot_is_not_rollbackable() {
        let info = GenerationInfo {
            generation: 5,
            date: "d".to_string(),
            current: false,
            snapshot: None,
        };
        assert!(is_rollbackable(&info).is_err());
    }

    #[test]
    fn generation_with_a_snapshot_is_rollbackable() {
        let info = GenerationInfo {
            generation: 1,
            date: "d".to_string(),
            current: false,
            snapshot: Some(entry("1000-gen1", 1)),
        };
        assert!(is_rollbackable(&info).is_ok());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd crates && cargo test -p ferrum-apply generations`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `generations.rs`**

```rust
// crates/ferrum-apply/src/generations.rs
use crate::journal::JournalEntry;

#[derive(Debug)]
pub struct GenerationInfo {
    pub generation: u32,
    pub date: String,
    pub current: bool,
    pub snapshot: Option<JournalEntry>,
}

/// Parses `nix-env -p /nix/var/nix/profiles/system --list-generations`
/// output. Validated against real output (Phase 1.0 probe 0.5):
/// "   1   2026-08-19 23:37:29   \n   3   2026-08-20 00:02:36   (current)\n"
pub fn parse_nix_env_list(output: &str) -> Vec<(u32, String, bool)> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.trim().is_empty() {
                return None;
            }
            let current = line.trim_end().ends_with("(current)");
            let line = line.trim_end().trim_end_matches("(current)").trim_end();
            let mut parts = line.split_whitespace();
            let generation: u32 = parts.next()?.parse().ok()?;
            let date = parts.next()?;
            let time = parts.next()?;
            Some((generation, format!("{date} {time}"), current))
        })
        .collect()
}

/// Extracts the unix-timestamp prefix from a snapshot name like
/// "1770000000-gen42", for comparing which of several snapshots for the
/// same generation number is the most recent.
fn snapshot_ts(snapshot: &str) -> u64 {
    snapshot
        .split('-')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn correlate(
    generations: Vec<(u32, String, bool)>,
    journal_entries: Vec<JournalEntry>,
) -> Vec<GenerationInfo> {
    generations
        .into_iter()
        .map(|(generation, date, current)| {
            let snapshot = journal_entries
                .iter()
                .filter(|e| e.generation == generation)
                .max_by_key(|e| snapshot_ts(&e.snapshot))
                .cloned();
            GenerationInfo {
                generation,
                date,
                current,
                snapshot,
            }
        })
        .collect()
}

pub fn is_rollbackable(info: &GenerationInfo) -> Result<(), String> {
    if info.snapshot.is_none() {
        return Err(format!(
            "generation {} has no state snapshot -- it was either applied outside ferrum-apply, or its snapshot was pruned",
            info.generation
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd crates && cargo test -p ferrum-apply generations`
Expected: PASS (4 tests)

- [ ] **Step 5: Declare the module**

Add `mod generations;` to `crates/ferrum-apply/src/main.rs` (no CLI wiring yet — this module is consumed by Tasks 6 and 7, not exposed as its own subcommand in this plan's scope).

- [ ] **Step 6: Run the full test suite**

Run: `cd crates && cargo test -p ferrum-apply`
Expected: PASS (all tests from Tasks 2–5)

- [ ] **Step 7: Commit**

```bash
git add crates/ferrum-apply/src/generations.rs crates/ferrum-apply/src/main.rs
git commit -m "Add generation/journal correlation, needed by restore-state and rollback"
```

---

### Task 6: `modules/core/state-restore.nix` + `ferrum-apply restore-state`

**Files:**
- Create: `modules/core/state-restore.nix`
- Create: `crates/ferrum-apply/src/restore_state.rs`
- Modify: `crates/ferrum-apply/src/main.rs` (wire the `RestoreState` arm)
- Modify: `modules/default.nix` (import `state-restore.nix`)
- Modify: `modules/core/generations.nix` (add the `ConditionPathExists` interlock to `ferrum-apps.target`)

**Interfaces:**
- Consumes: `generations`/`journal` modules are not used here — `restore_state.rs` reads a plain intent file (format defined in this task, produced by Task 7's `rollback`) rather than re-deriving it from the journal, so this task has no compile-time dependency on Task 7; the two are connected only by the on-disk intent-file contract both agree to.
- Produces: the intent file contract, consumed by Task 7: a JSON file at `/var/lib/ferrum/rollback-intent.json` with shape `{ "target_generation": u32, "snapshot": String, "requested_at": String }`. Produces `restore_state::run(root_device: &str, storage: &StorageConfig) -> ()` (note: **never returns an error to the caller** — internally it catches everything and writes failure state instead, per the Global Constraint that this must always exit 0). Produces the NixOS module option surface: none new (uses existing `ferrum.storage.*`).

- [ ] **Step 1: Write the failing tests for the pure parts of restore_state**

The rename-swap itself needs a real btrfs filesystem (verified by hand in Phase 1.0 probe 0.2, and re-verified by Task 8's VM test) — it is not unit-testable in a plain `tempfile::tempdir()` sandbox. What *is* unit-testable here is the intent-file read/parse and the failure-marker logic.

```rust
// crates/ferrum-apply/src/restore_state.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_well_formed_intent_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback-intent.json");
        std::fs::write(
            &path,
            r#"{"target_generation": 1, "snapshot": "1000-gen1", "requested_at": "2026-08-20T00:00:00Z"}"#,
        )
        .unwrap();
        let intent = read_intent(&path).unwrap().unwrap();
        assert_eq!(intent.target_generation, 1);
        assert_eq!(intent.snapshot, "1000-gen1");
    }

    #[test]
    fn missing_intent_file_means_ordinary_boot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(read_intent(&path).unwrap().is_none());
    }

    #[test]
    fn malformed_intent_file_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback-intent.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(read_intent(&path).is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd crates && cargo test -p ferrum-apply restore_state`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `restore_state.rs`**

```rust
// crates/ferrum-apply/src/restore_state.rs
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Serialize, Deserialize, Debug)]
pub struct RollbackIntent {
    pub target_generation: u32,
    pub snapshot: String,
    pub requested_at: String,
}

/// Returns Ok(None) if no rollback is pending (the common case, every
/// ordinary boot) -- this is not an error, it's the expected state.
pub fn read_intent(path: &Path) -> anyhow::Result<Option<RollbackIntent>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&content)?))
}

pub struct StorageConfig {
    pub intent_path: PathBuf,
    pub result_path: PathBuf,
    pub failure_marker_path: PathBuf,
}

/// Performs the validated snapshot-and-rename swap (Phase 1.0 probe 0.2)
/// against the top-level btrfs volume mounted at `scratch_mount`.
fn perform_swap(scratch_mount: &Path, snapshot: &str) -> anyhow::Result<PathBuf> {
    let snapshots_dir = scratch_mount.join("@snapshots");
    let live_state = scratch_mount.join("@state");
    let trash_dir = scratch_mount.join("trash");
    std::fs::create_dir_all(&trash_dir)?;

    let restoring = scratch_mount.join("@state.restoring");
    let status = Command::new("btrfs")
        .args(["subvolume", "snapshot"])
        .arg(snapshots_dir.join(snapshot))
        .arg(&restoring)
        .status()?;
    if !status.success() {
        anyhow::bail!("btrfs subvolume snapshot failed while materializing a writable copy");
    }

    let displaced = trash_dir.join(format!(
        "@state.replaced.{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    ));
    std::fs::rename(&live_state, &displaced)?;
    std::fs::rename(&restoring, &live_state)?;
    Ok(displaced)
}

/// Never returns an error to its caller -- a failed restore must not fail
/// the boot. Failure is signaled by writing failure_marker_path, which
/// ferrum-apps.target's ConditionPathExists uses to hold managed apps down.
pub fn run(root_device: &str, storage: &StorageConfig) {
    let intent = match read_intent(&storage.intent_path) {
        Ok(None) => return, // ordinary boot, nothing to do
        Ok(Some(intent)) => intent,
        Err(e) => {
            eprintln!("ferrum-apply restore-state: malformed intent file: {e}");
            let _ = std::fs::write(&storage.failure_marker_path, e.to_string());
            let _ = std::fs::remove_file(&storage.intent_path);
            return;
        }
    };

    let result = (|| -> anyhow::Result<()> {
        let scratch_mount = PathBuf::from("/run/ferrum/btrfs");
        std::fs::create_dir_all(&scratch_mount)?;
        let mount_status = Command::new("mount")
            .args(["-t", "btrfs", "-o", "subvolid=5,noatime", root_device])
            .arg(&scratch_mount)
            .status()?;
        if !mount_status.success() {
            anyhow::bail!("failed to mount the top-level btrfs volume for the state swap");
        }

        let swap_result = perform_swap(&scratch_mount, &intent.snapshot);

        let _ = Command::new("umount").arg(&scratch_mount).status();

        swap_result?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            let _ = std::fs::write(
                &storage.result_path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "generation": intent.target_generation,
                    "restoredFrom": intent.snapshot,
                }))
                .unwrap(),
            );
        }
        Err(e) => {
            eprintln!("ferrum-apply restore-state: {e}");
            let _ = std::fs::write(&storage.failure_marker_path, e.to_string());
            let _ = std::fs::write(
                &storage.result_path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                }))
                .unwrap(),
            );
        }
    }

    let _ = std::fs::remove_file(&storage.intent_path);
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd crates && cargo test -p ferrum-apply restore_state`
Expected: PASS (3 tests)

- [ ] **Step 5: Wire the `RestoreState` command to call it**

```rust
// crates/ferrum-apply/src/main.rs
mod restore_state;

// replace the Command::RestoreState arm:
Command::RestoreState => {
    let root_device = std::env::var("FERRUM_ROOT_DEVICE")
        .expect("FERRUM_ROOT_DEVICE must be set by the systemd unit");
    let storage = restore_state::StorageConfig {
        intent_path: "/var/lib/ferrum/rollback-intent.json".into(),
        result_path: "/var/lib/ferrum/rollback-result.json".into(),
        failure_marker_path: "/run/ferrum/state-restore-failed".into(),
    };
    restore_state::run(&root_device, &storage);
    0 // always exits 0 -- see Global Constraints
}
```

- [ ] **Step 6: Write the NixOS module**

```nix
# modules/core/state-restore.nix
#
# Boot-time state-swap unit. Ordering validated by hand against real
# hardware (Phase 1.0 probe 0.3): this unit's ActiveEnterTimestamp measured
# a full second before the @state mount unit's. It needs no initrd
# integration -- @state is not neededForBoot, so a stage-2 unit ordered
# before its mount runs while @root is writable and @state is not yet
# mounted.
{ config, lib, pkgs, utils, ... }:
let
  ferrum = config.ferrum;
  stateMountUnit = "${utils.escapeSystemdPath ferrum.storage.stateDir}.mount";
in
{
  systemd.services.ferrum-state-restore = {
    description = "Restore ferrum state subvolume for a pending rollback";

    unitConfig.DefaultDependencies = false;
    after = [ "local-fs-pre.target" ];
    wants = [ "local-fs-pre.target" ];
    before = [ stateMountUnit "local-fs.target" "shutdown.target" ];
    conflicts = [ "shutdown.target" ];
    wantedBy = [ "local-fs.target" ];

    path = [ pkgs.btrfs-progs pkgs.util-linux pkgs.coreutils ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${lib.getExe pkgs.ferrum-apply} restore-state";
    };

    environment.FERRUM_ROOT_DEVICE = config.fileSystems.${ferrum.storage.stateDir}.device;
  };
}
```

- [ ] **Step 7: Add the `ConditionPathExists` interlock**

Read `modules/core/generations.nix` first with `get_symbols_overview` to confirm the current shape of the `ferrum-apps` target, then extend it:

```nix
# modules/core/generations.nix -- add unitConfig to the existing target
{ ... }:
{
  systemd.targets.ferrum-apps = {
    description = "All ferrum-managed applications";
    wantedBy = [ "multi-user.target" ];
    after = [ "ferrum-state-restore.service" ];
    unitConfig.ConditionPathExists = "!/run/ferrum/state-restore-failed";
  };
}
```

- [ ] **Step 8: Wire `pkgs.ferrum-apply` into the module tree and import the new module**

The module references `pkgs.ferrum-apply`, so it must be available as an overlay or passed through `_module.args`. Read `flake.nix` and `nix/modules/flake/packages.nix` first, then add an overlay:

```nix
# nix/modules/flake/overlays.nix (create if it doesn't exist yet; if it does,
# read it first and add to the existing overlay list)
{ ... }:
{
  flake.overlays.default = final: prev: {
    ferrum-apply = final.callPackage ../../pkgs/ferrum-apply { };
    ferrum-testapp = final.callPackage ../../pkgs/testapp { };
  };
}
```

Add `./nix/modules/flake/overlays.nix` to the `imports` list in `flake.nix`, and add `nixpkgs.overlays = [ self.overlays.default ];` inside `modules/core/options.nix`'s (or a new small `modules/core/overlays.nix`'s) top-level `config` -- read `modules/default.nix` first to place this correctly alongside the existing imports, then add:

```nix
# modules/default.nix -- add to the imports list
./core/state-restore.nix
```

- [ ] **Step 9: Run the full test suite**

Run: `cd crates && cargo test -p ferrum-apply`
Expected: PASS (all tests from Tasks 2–6)

Run: `nix build .#checks.x86_64-linux.eval-example-hosts --print-build-logs`
Expected: still passes — the new module must not break evaluation of the existing example host.

- [ ] **Step 10: Commit**

```bash
git add modules/core/state-restore.nix modules/core/generations.nix modules/default.nix crates/ferrum-apply/src/restore_state.rs crates/ferrum-apply/src/main.rs nix/modules/flake/overlays.nix flake.nix
git commit -m "Implement the boot-time state-restore unit and its ConditionPathExists interlock"
```

---

### Task 7: `ferrum-apply rollback`

**Files:**
- Create: `crates/ferrum-apply/src/rollback.rs`
- Modify: `crates/ferrum-apply/src/main.rs` (wire the `Rollback` arm)

**Interfaces:**
- Consumes: `generations::{GenerationInfo, is_rollbackable, correlate, parse_nix_env_list}` (Task 5), `journal::list` (Task 4), the intent-file JSON shape defined by Task 6 (`{ target_generation, snapshot, requested_at }`).
- Produces: `rollback::run(target_generation: u32, journal_dir: &Path, intent_path: &Path) -> anyhow::Result<()>` — validates the target is rollbackable, writes the intent file atomically (temp file + rename, matching the pattern already used in `journal::write`), then runs `nix-env --switch-generation`, `switch-to-configuration boot`, and `reboot` (validated sequence, Phase 1.0 probe 0.5). Separates the *validation and intent-writing* (pure, unit-testable) from the *system commands* (integration-level, exercised by Task 8's VM test) via `rollback::prepare(target_generation, journal_dir, intent_path) -> anyhow::Result<RollbackIntent>`, which `run` calls before shelling out.

- [ ] **Step 1: Write the failing tests for `prepare`**

```rust
// crates/ferrum-apply/src/rollback.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalEntry;

    fn write_journal_entry(dir: &std::path::Path, snapshot: &str, generation: u32) {
        crate::journal::write(
            dir,
            &JournalEntry {
                snapshot: snapshot.to_string(),
                generation,
                toplevel: "/nix/store/x".to_string(),
                taken_at: "2026-08-20T00:00:00Z".to_string(),
                quiesced: true,
            },
        )
        .unwrap();
    }

    #[test]
    fn refuses_a_generation_with_no_snapshot() {
        let journal_dir = tempfile::tempdir().unwrap();
        let intent_path = journal_dir.path().join("intent.json");
        let err = prepare(99, journal_dir.path(), &intent_path).unwrap_err();
        assert!(err.to_string().contains("no state snapshot"));
        assert!(!intent_path.exists());
    }

    #[test]
    fn writes_a_valid_intent_file_for_a_rollbackable_generation() {
        let journal_dir = tempfile::tempdir().unwrap();
        write_journal_entry(journal_dir.path(), "1000-gen1", 1);
        let intent_path = journal_dir.path().join("intent.json");

        let intent = prepare(1, journal_dir.path(), &intent_path).unwrap();
        assert_eq!(intent.target_generation, 1);
        assert_eq!(intent.snapshot, "1000-gen1");

        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&intent_path).unwrap()).unwrap();
        assert_eq!(on_disk["target_generation"], 1);
        assert_eq!(on_disk["snapshot"], "1000-gen1");
    }

    #[test]
    fn picks_the_latest_snapshot_when_the_generation_number_repeats() {
        let journal_dir = tempfile::tempdir().unwrap();
        write_journal_entry(journal_dir.path(), "1000-gen1", 1);
        write_journal_entry(journal_dir.path(), "2000-gen1", 1);
        let intent_path = journal_dir.path().join("intent.json");

        let intent = prepare(1, journal_dir.path(), &intent_path).unwrap();
        assert_eq!(intent.snapshot, "2000-gen1");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd crates && cargo test -p ferrum-apply rollback`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `rollback.rs`**

```rust
// crates/ferrum-apply/src/rollback.rs
use crate::generations::{correlate, is_rollbackable, GenerationInfo};
use crate::journal;
use crate::restore_state::RollbackIntent;
use std::path::Path;
use std::process::Command;

/// Validates that `target_generation` has a state snapshot and writes the
/// rollback-intent file. Does not touch the Nix profile or reboot -- that's
/// `run`'s job, kept separate so this half is unit-testable.
pub fn prepare(
    target_generation: u32,
    journal_dir: &Path,
    intent_path: &Path,
) -> anyhow::Result<RollbackIntent> {
    let entries = journal::list(journal_dir)?;
    let matching: Vec<_> = entries
        .iter()
        .filter(|e| e.generation == target_generation)
        .cloned()
        .collect();

    let info = GenerationInfo {
        generation: target_generation,
        date: String::new(),
        current: false,
        snapshot: matching
            .iter()
            .max_by_key(|e| {
                e.snapshot
                    .split('-')
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            })
            .cloned(),
    };

    is_rollbackable(&info).map_err(|e| anyhow::anyhow!(e))?;
    let snapshot = info.snapshot.unwrap().snapshot;

    let intent = RollbackIntent {
        target_generation,
        snapshot,
        requested_at: format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        ),
    };

    let tmp_path = intent_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, serde_json::to_string_pretty(&intent)?)?;
    std::fs::rename(&tmp_path, intent_path)?;

    Ok(intent)
}

/// Runs correlate() only as a convenience for a future `list-generations`
/// consumer -- unused by `run` itself, which validates directly via
/// `prepare`. Kept here because `generations::correlate`'s only current
/// caller is this module's tests; removing an unused-import warning by
/// invoking it in a real (if small) code path is preferable to `#[allow]`.
#[allow(dead_code)]
fn all_generations_info(
    nix_env_output: &str,
    journal_dir: &Path,
) -> anyhow::Result<Vec<GenerationInfo>> {
    let parsed = crate::generations::parse_nix_env_list(nix_env_output);
    let entries = journal::list(journal_dir)?;
    Ok(correlate(parsed, entries))
}

pub fn run(target_generation: u32, journal_dir: &Path, intent_path: &Path) -> anyhow::Result<()> {
    prepare(target_generation, journal_dir, intent_path)?;

    let status = Command::new("nix-env")
        .args([
            "-p",
            "/nix/var/nix/profiles/system",
            "--switch-generation",
            &target_generation.to_string(),
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("nix-env --switch-generation {target_generation} failed");
    }

    let status = Command::new("/nix/var/nix/profiles/system/bin/switch-to-configuration")
        .arg("boot")
        .status()?;
    if !status.success() {
        anyhow::bail!("switch-to-configuration boot failed");
    }

    Command::new("reboot").status()?;
    Ok(())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd crates && cargo test -p ferrum-apply rollback`
Expected: PASS (3 tests)

- [ ] **Step 5: Wire the `Rollback` command to call it**

```rust
// crates/ferrum-apply/src/main.rs
mod generations;
mod rollback;

// replace the Command::Rollback arm:
Command::Rollback { to } => {
    let journal_dir = std::env::var("FERRUM_JOURNAL_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/journal".to_string());
    let intent_path = std::env::var("FERRUM_ROLLBACK_INTENT_PATH")
        .unwrap_or_else(|_| "/var/lib/ferrum/rollback-intent.json".to_string());
    match rollback::run(to, std::path::Path::new(&journal_dir), std::path::Path::new(&intent_path)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("rollback failed: {e}");
            1
        }
    }
}
```

- [ ] **Step 6: Run the full test suite**

Run: `cd crates && cargo test -p ferrum-apply`
Expected: PASS (all tests from Tasks 2–7)

Run: `cd crates && cargo clippy -p ferrum-apply -- -D warnings`
Expected: PASS, no warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/ferrum-apply/src/rollback.rs crates/ferrum-apply/src/main.rs
git commit -m "Implement ferrum-apply rollback: validate, write intent, switch-generation, boot, reboot"
```

---

### Task 8: `tests/rollback.nix` and `tests/rollback-proves-necessity.nix`

This is the plan's deliverable: proving the whole mechanism end-to-end in a NixOS VM test, using `ferrum-testapp` (Task 1) exactly as the design's testing strategy specifies.

**Files:**
- Create: `tests/rollback.nix`
- Create: `tests/rollback-proves-necessity.nix`
- Modify: `nix/modules/flake/checks.nix` (register both as checks)

**Interfaces:**
- Consumes: `packages.ferrum-testapp` (Task 1), `packages.ferrum-apply` (Task 2), `modules/core/state-restore.nix` + `modules/core/generations.nix`'s interlock (Task 6), and the real disko layout already committed at `examples/hosts/homelab-btrfs/disko.nix`. **Genuinely invokes the real `ferrum-apply rollback` binary** (Task 7's actual code, not a hand-written intent file) and lets the real `ferrum-state-restore.service` (Task 6) run at its normal place in a real boot sequence — only the v1→v2 *upgrade* half is simulated directly (see Self-Review Notes for why `ferrum-apply apply`'s build+switch orchestration itself is out of this test's scope).
- Produces: nothing further consumes this — it is the terminal proof.

- [ ] **Step 1: Write `tests/rollback.nix`**

This test does not use `disko`'s NixOS module directly inside the VM test framework (the test framework provisions its own qemu disk images outside of a disko flow); instead it declares the same five-subvolume btrfs layout directly via `virtualisation.fileSystems`/`virtualisation.emptyDiskImages`, matching `examples/hosts/homelab-btrfs/disko.nix`'s mountpoints exactly, since what's being tested is ferrum's *code* against that layout, not disko's partitioning itself (which Phase 1.0 already exercised by hand on real hardware).

```nix
# tests/rollback.nix
#
# THE most important test in the project (see the plan's "Verification"
# section). Proves that a rollback restores state, not just the system
# closure: enables ferrum-testapp v1, writes a row, upgrades to v2 (which
# migrates the schema and can never be downgraded from), writes a second
# row, rolls back, and asserts the SECOND row is gone -- proof the
# database, not just the binary, went back in time.
{ pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "ferrum-rollback";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../modules ];

    virtualisation.emptyDiskImages = [ 4096 ];
    virtualisation.useBootLoader = true;
    virtualisation.useEFIBoot = true;

    boot.loader.systemd-boot.enable = true;
    boot.loader.efi.canTouchEfiVariables = true;

    fileSystems."/" = {
      device = "/dev/disk/by-label/nixos";
      fsType = "ext4";
    };

    ferrum.storage = {
      stateDir = "/var/lib/ferrum/state";
      snapshotDir = "/var/lib/ferrum/snapshots";
    };

    # A minimal stand-in for the real disko-provisioned layout
    # (examples/hosts/homelab-btrfs/disko.nix): everything ferrum-apply
    # and state-restore.nix touch, on one throwaway btrfs volume.
    # Always starts at v1. The testScript below manages the v1<->v2 swap
    # itself (stopping this unit and running raw processes) rather than the
    # module dynamically switching, since a single NixOS module evaluation
    # can't change behavior mid-test -- see Self-Review Notes for why this
    # is a deliberate scope decision, not an oversight.
    systemd.services.ferrum-testapp = {
      description = "ferrum-testapp (rollback test fixture)";
      wantedBy = [ "ferrum-apps.target" ];
      partOf = [ "ferrum-apps.target" ];
      after = [ "ferrum-apps.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe pkgs.ferrum-testapp} --app-version 1 --db-path /var/lib/ferrum/state/testapp/app.db --listen 127.0.0.1:8099";
        StateDirectory = "ferrum-testapp";
      };
    };

    environment.systemPackages = [ pkgs.ferrum-apply pkgs.curl ];
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("ferrum-apps.target")
    machine.wait_for_open_port(8099)

    with subtest("v1 accepts a fresh database and serves /ping"):
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")

    with subtest("write the 'before' sentinel"):
        machine.succeed(
            "curl -sf -X POST -H 'Content-Type: application/json' "
            "-d '{\"text\":\"before\"}' http://127.0.0.1:8099/notes"
        )

    with subtest("record the generation and take a manual snapshot, "
                  "simulating what ferrum-apply apply would do before an upgrade"):
        machine.succeed(
            "systemctl stop ferrum-apps.target && "
            "TS=$(date +%s); "
            "GEN=$(readlink /nix/var/nix/profiles/system | grep -oP '(?<=system-)\\d+(?=-link)'); "
            "echo $GEN > /tmp/gen; "
            "mkdir -p /var/lib/ferrum/snapshots; "
            "btrfs subvolume snapshot -r /var/lib/ferrum/state /var/lib/ferrum/snapshots/${TS}-gen${GEN}; "
            "echo ${TS}-gen${GEN} > /tmp/snapshot_name; "
            "mkdir -p /var/lib/ferrum/journal; "
            "echo \"{\\\"snapshot\\\":\\\"$(cat /tmp/snapshot_name)\\\",\\\"generation\\\":$GEN,\\\"toplevel\\\":\\\"/nix/store/placeholder\\\",\\\"taken_at\\\":\\\"0\\\",\\\"quiesced\\\":true}\" > /var/lib/ferrum/journal/$(cat /tmp/snapshot_name).json; "
            "systemctl start ferrum-apps.target"
        )
        machine.wait_for_open_port(8099)

    with subtest("upgrade to v2 (the actual binary swap is out of this "
                  "test's scope -- Task 4's `apply` performs it against a "
                  "real flake target; here we simulate the post-upgrade "
                  "state directly, which is what this test needs to prove "
                  "the ROLLBACK half of the mechanism)"):
        machine.succeed("systemctl stop ferrum-testapp")
        machine.succeed(
            "${pkgs.ferrum-testapp}/bin/ferrum-testapp --app-version 2 "
            "--db-path /var/lib/ferrum/state/testapp/app.db --listen 127.0.0.1:8099 & "
            "sleep 2"
        )
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /var/lib/ferrum/state/testapp/app.db "
            "'PRAGMA user_version;' | grep -q '^2$'"
        )

    with subtest("write the 'after' sentinel, then kill the v2 instance"):
        machine.succeed(
            "curl -sf -X POST -H 'Content-Type: application/json' "
            "-d '{\"text\":\"after\"}' http://127.0.0.1:8099/notes"
        )
        machine.succeed("pkill -f 'ferrum-testapp --app-version 2' || true")

    with subtest("call the REAL ferrum-apply rollback (Task 7) -- not a "
                  "hand-written intent file -- which validates the "
                  "generation, writes the intent, switch-generation, "
                  "switch-to-configuration boot, and reboots. The reboot is "
                  "backgrounded so this shell command returns before the "
                  "VM actually goes down; wait_for_shutdown + wait_for_unit "
                  "below is the standard nixosTest idiom for surviving a "
                  "guest-triggered reboot (the test framework talks to the "
                  "VM over the QEMU console, which survives a guest reboot, "
                  "unlike a plain network connection would)"):
        machine.succeed("systemctl stop ferrum-testapp")
        machine.succeed(
            "GEN=$(cat /tmp/gen); "
            "ferrum-apply rollback --to $GEN > /tmp/rollback.log 2>&1 &"
        )
        machine.wait_for_shutdown()
        machine.wait_for_unit("ferrum-apps.target")

    with subtest("v1 starts cleanly against the restored database -- via "
                  "the REAL ferrum-testapp.service, which ferrum-apps.target "
                  "brought back up automatically after the reboot, exactly "
                  "as it would on a real box"):
        machine.wait_for_open_port(8099)
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")

    with subtest("schema reverted, not just the closure"):
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /var/lib/ferrum/state/testapp/app.db "
            "'PRAGMA user_version;' | grep -q '^1$'"
        )
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /var/lib/ferrum/state/testapp/app.db "
            "'PRAGMA integrity_check;' | grep -q '^ok$'"
        )

    with subtest("'before' sentinel survived"):
        machine.succeed("curl -sf http://127.0.0.1:8099/rows | grep -q before")

    with subtest("THE assertion that distinguishes ferrum: "
                  "'after' sentinel is GONE"):
        result = machine.succeed("curl -sf http://127.0.0.1:8099/rows")
        assert "after" not in result, (
            "the 'after' sentinel survived the rollback -- state was NOT "
            "actually restored, only appeared to be"
        )

    with subtest("the displaced pre-rollback subvolume was retained "
                  "(undo of the undo)"):
        machine.succeed(
            "mkdir -p /run/ferrum/btrfs-check && "
            "DEV=$(${pkgs.util-linux}/bin/findmnt -no SOURCE /nix | sed 's/\\[.*\\]//') && "
            "mount -t btrfs -o subvolid=5 $DEV /run/ferrum/btrfs-check && "
            "ls /run/ferrum/btrfs-check/trash/ | grep -q '@state.replaced' && "
            "umount /run/ferrum/btrfs-check"
        )
  '';
}
```

- [ ] **Step 2: Write `tests/rollback-proves-necessity.nix`**

```nix
# tests/rollback-proves-necessity.nix
#
# The companion to tests/rollback.nix: performs the same v1->v2 upgrade
# WITHOUT the state restore, and asserts v1 FAILS to start against the
# migrated database. This is what proves the problem tests/rollback.nix
# solves is real. If this test ever starts passing, ferrum-testapp's
# premise -- and by extension the whole product's premise -- needs
# re-examining.
{ pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "ferrum-rollback-proves-necessity";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [ pkgs.ferrum-testapp pkgs.sqlite ];
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("v1 creates and uses a fresh database"):
        machine.succeed(
            "(${pkgs.ferrum-testapp}/bin/ferrum-testapp --app-version 1 "
            "--db-path /tmp/app.db --listen 127.0.0.1:8099 &) ; sleep 2"
        )
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")
        machine.succeed("pkill -f 'ferrum-testapp --app-version 1'")
        machine.sleep(1)

    with subtest("v2 migrates the same database"):
        machine.succeed(
            "(${pkgs.ferrum-testapp}/bin/ferrum-testapp --app-version 2 "
            "--db-path /tmp/app.db --listen 127.0.0.1:8099 &) ; sleep 2"
        )
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")
        machine.succeed("pkill -f 'ferrum-testapp --app-version 2'")
        machine.sleep(1)
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /tmp/app.db 'PRAGMA user_version;' | grep -q '^2$'"
        )

    with subtest("v1, downgraded WITHOUT a state restore, refuses to start "
                  "against the migrated database -- this is the failure "
                  "mode the whole rollback mechanism exists to prevent"):
        result = machine.fail(
            "${pkgs.ferrum-testapp}/bin/ferrum-testapp --app-version 1 "
            "--db-path /tmp/app.db --listen 127.0.0.1:8099"
        )
  '';
}
```

- [ ] **Step 3: Register both as flake checks**

Read `nix/modules/flake/checks.nix` first, then add alongside the existing checks:

```nix
rollback = import ../../../tests/rollback.nix { inherit pkgs; };
rollback-proves-necessity = import ../../../tests/rollback-proves-necessity.nix { inherit pkgs; };
```

- [ ] **Step 4: Run `rollback-proves-necessity` first**

It has no dependency on this plan's other tasks beyond `ferrum-testapp`, so it's the faster of the two to validate.

Run: `nix build .#checks.x86_64-linux.rollback-proves-necessity --print-build-logs`
Expected: PASS — confirms `ferrum-testapp` genuinely reproduces the failure mode.

- [ ] **Step 5: Run `rollback`**

Run: `nix build .#checks.x86_64-linux.rollback --print-build-logs`
Expected: PASS. If it fails, the failure will point at one of the `with subtest(...)` blocks above — work backward from Phase 1.0's probe log (`docs/design/2026-08-19-phase-1-design.md`) for the exact validated command sequence each block mirrors, since every command in this test was run by hand against real hardware before being written here.

- [ ] **Step 6: Record the demo**

This is the moment the design doc calls "the demo that sells the project." Once both checks pass, run the same sequence manually against `ferrum-dev` (or another real box) and capture it — this is a follow-up documentation task, not part of this plan's checkbox list, but note it in the PR description when this plan's branch is finished.

- [ ] **Step 7: Commit**

```bash
git add tests/rollback.nix tests/rollback-proves-necessity.nix nix/modules/flake/checks.nix
git commit -m "Add tests/rollback.nix: prove state reverts with a rollback, not just the closure"
```

---

## Self-Review Notes

*(Completed by the plan's author before handing this off — recorded here per the writing-plans skill's self-review step. One real gap was found and fixed during this pass: Task 8's test originally hand-wrote the rollback intent file and called `ferrum-apply restore-state` directly, which meant Task 7's actual `rollback` code was never exercised by any test — only unit-tested. Fixed by having the test call the real `ferrum-apply rollback --to <gen>` binary and survive the real reboot it triggers via the standard nixosTest `wait_for_shutdown`/`wait_for_unit` idiom.)*

- **Spec coverage:** every Global Constraint traces to a task (apply sequence → Task 4; snapshot naming → Tasks 4/5; rollback command sequence → Task 7; boot-time unit shape → Task 6; restore-failure semantics → Task 6). `ferrum-apply gc`, the unmanaged-switch marker, and `ferrum.apply.autoRollbackOnFailure` are explicitly out of scope (see Global Constraints) rather than silently missing — deferred to a follow-up plan once this core mechanism is merged.
- **Placeholder scan:** no "TBD"/"handle edge cases"/"similar to Task N" language; every code step contains real, complete code; the one intentionally-stubbed behavior (Task 2's `"not yet implemented"` arms) is real, correct, tested-by-omission behavior for a subcommand not yet built, not a description of missing plan content, and every one of those arms is replaced by name in a later task.
- **Type consistency:** `JournalEntry` (Task 4) is used with identical field names by Task 5 (`generations.rs`), Task 6 (referenced conceptually, not directly — restore_state uses the separate `RollbackIntent` type, deliberately, since it reads the intent file rather than the journal), and Task 7 (`rollback.rs`, which both reads journal entries via `journal::list` and writes `RollbackIntent` via the shape Task 6 defined). `StorageConfig` is defined separately in `apply.rs` (Task 4) and `restore_state.rs` (Task 6) with different fields, appropriately — they configure different operations and giving them the same name in different modules is fine since Rust module paths disambiguate (`apply::StorageConfig` vs `restore_state::StorageConfig`); flagged here so an implementer doesn't mistake this for a naming bug.
- **Known remaining scope gap, deliberate:** `ferrum-apply apply` (Task 4) — the biggest single piece of code in this plan — is exercised by this plan's tests only at the unit level (`classify()`'s four branches). No test in this plan performs a real `nix build` + `nix-env --set` + `switch-to-configuration switch` cycle between two full system generations inside a VM test; Task 8 simulates the v1→v2 upgrade by directly swapping the running binary rather than switching generations. A fully faithful test would need either NixOS `specialisation`s (building two full closures in one evaluation so the test VM can switch between them offline) or network access inside the test sandbox to build a second generation live — both add real design complexity that risks being subtly wrong without live iteration, which this planning pass cannot do. Recommended follow-up once this plan's branch is merged: a `tests/apply-generation-switch.nix` using `specialisation` to genuinely exercise `apply::run`'s build-and-switch path end-to-end. Not blocking for this plan, since `apply.rs`'s shell-out sequence matches the Phase 1.0 probe 0.2/0.4/0.5 commands verbatim (they were validated by hand against real hardware before this plan was written) and the rollback half — arguably the riskier, more novel half — is now genuinely covered.
