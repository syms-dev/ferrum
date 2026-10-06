use clap::{Parser, Subcommand};

mod address_history;
mod apply;
mod dns_reconcile;
mod gc;
mod pin;
mod pin_gate;
mod preflight;
mod progress;
mod put_secret;
mod request;
mod restore_state;
mod rollback;
mod secrets;
mod update_apply;
mod update_candidate;
mod update_check;
mod update_deltas;

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
    Apply {
        /// Acknowledge that this rebuild also moves the host to a different
        /// ferrum revision, naming that revision exactly.
        ///
        /// Only consulted when the on-disk pin and the pin the running
        /// generation was built from actually disagree (R8); on every other
        /// host it changes nothing. See `pin_gate` for why the gate is
        /// passable rather than a wall.
        #[arg(long, value_name = "REV")]
        accept_pin_change: Option<String>,
    },
    /// Schedule a reboot into an earlier generation with its matching state.
    Rollback {
        #[arg(long)]
        to: u32,
    },
    /// Run at boot: perform a pending state restore, if one is scheduled.
    RestoreState,
    /// Prune old generations and their snapshots together.
    Gc,
    /// Read a JSON request file (written by ferrumd) and dispatch to the
    /// matching existing subcommand's logic. This is the ONLY entry point
    /// ferrumd itself ever triggers -- see modules/core/daemon.nix for the
    /// polkit rule and systemd template unit that authorize it.
    RunRequest {
        path: std::path::PathBuf,
    },
    /// Encrypt an OPERATOR-SUPPLIED secret value, read from stdin, to this
    /// host's own age recipient and write <secretsDir>/<name>.sops.
    ///
    /// Every other secret this binary handles is one it generates itself.
    /// This is the path for a value only a human has -- today, the
    /// Cloudflare DNS-01 token, without which a host with any `public` app
    /// cannot even evaluate (modules/proxy/acme.nix asserts the .sops file
    /// exists at Nix eval time).
    ///
    /// The value comes from stdin, never argv, so it stays out of `ps` and
    /// shell history. Existing files are left alone unless --replace is
    /// given, which keeps a resumed install idempotent.
    PutSecret {
        /// Secret name, e.g. `acme-dns`. Must match the name declared in
        /// settings.json's `secrets` map.
        name: String,
        /// Overwrite an existing value (use when rotating a credential).
        #[arg(long)]
        replace: bool,
    },
    /// Reconcile the DNS records this host publishes against Cloudflare.
    ///
    /// Invoked on a schedule by `ferrum-dns-updater.service`
    /// (`modules/proxy/dns.nix`) to correct the A records ferrum owns when
    /// this host's public address moves. `ferrum-apply apply` does the same
    /// work in-process after every switch; this is that reconciliation
    /// *between* applies, and it is safe to run by hand at any time.
    ///
    /// Takes a path, never a credential: the token is read from the file the
    /// document names, so it never appears in argv and never reaches `ps`.
    ReconcileDns {
        /// The desired-record document, normally
        /// `/etc/ferrum-dns-config.json`.
        #[arg(long)]
        config: std::path::PathBuf,
    },
    /// Show what a settings.json schema migration would do, without
    /// writing anything. Read-only: evaluates the real flake via `nix
    /// eval`, never runs `nix build` or touches settings.json on disk.
    PreviewMigration,
    /// Report what this host runs today and what an update would change,
    /// without changing anything.
    ///
    /// Strictly read-only: `nix eval` only, no `nix build`, no
    /// `nix flake lock`, and provably no write to /etc/ferrum/flake.nix or
    /// /etc/ferrum/flake.lock -- the two files the privilege boundary
    /// exists to protect. Exists as a subcommand as well as a request kind
    /// so `request::Request`'s own rule holds: every variant maps onto a
    /// subcommand an operator can also run by hand over SSH.
    CheckUpdate,
    /// Advance this host's ferrum pin to the newest tested release and
    /// apply it, as one action.
    ///
    /// Writes `/etc/ferrum/flake.lock` and nothing else, then runs the
    /// ordinary apply pipeline -- an update is not a special case of the
    /// rollback story, it is an ordinary instance of it. Refuses if the
    /// flake directory has uncommitted changes, if the candidate is not
    /// strictly newer, if the advance would repoint the input at a
    /// different repository, or if it lands on a revision other than the
    /// one just resolved; every refusal leaves `flake.lock` untouched.
    Update,
    /// Confirm the update this host is running is good, releasing the
    /// snapshots `gc` was holding back for it.
    ///
    /// An update's way back is the state snapshot taken immediately before
    /// its pin moved, and `ferrum.storage.keepGenerations` retires that
    /// after ten more applies. So an update commit marks its pre-image and
    /// `gc` refuses to prune a marked snapshot; this is the other end of
    /// that, and the reason the exception is bounded rather than a
    /// retention rule that grows for the life of the host.
    ///
    /// Reversible in the only direction that matters: it releases snapshots
    /// to ORDINARY retention, so a confirmed update is still rollbackable
    /// for as long as any other change of the same age is.
    ConfirmUpdate,
}

/// Writes the job's `started` line, then runs it.
///
/// Extracted from the `RunRequest` arm -- the way this file already extracts
/// `handle_apply_result` and `restore_state_outcome` -- so that the ORDERING
/// is testable: the `started` line must be the first line of a dispatched
/// job's file, before any subcommand writes progress of its own. `GET
/// /api/jobs` reads that first line to answer "what was this job?", and by
/// then ferrumd has already deleted the request file that would otherwise
/// have said.
///
/// The kind comes from the parsed `Request`, never re-derived from the raw
/// file text. `Progress` is passed in rather than opened here so the test
/// below needs no process-wide environment; in production it is
/// `Progress::open()`, which is a total no-op when `FERRUM_JOB_ID` is unset,
/// so a bare `ferrum-apply run-request` over SSH still writes nothing.
fn run_request(
    req: request::Request,
    progress: &mut progress::Progress,
    run: impl FnOnce(request::Request) -> i32,
) -> i32 {
    progress.event("started", req.kind());
    run(req)
}

/// Maps an `apply::run` outcome to a process exit code, printing context to
/// stderr along the way. `Degraded` gets its own distinct code (3) so a
/// caller (a systemd unit, future automation) can tell "switched but a unit
/// is down" apart from a clean success without parsing stderr text.
fn handle_apply_result(result: anyhow::Result<apply::ApplyResult>) -> i32 {
    match result {
        Ok(apply::ApplyResult::Succeeded) => 0,
        Ok(apply::ApplyResult::Degraded(reason)) => {
            eprintln!("apply degraded: {reason}");
            3
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

/// Every request kind dispatched via `run-request` must terminate its own
/// JSONL progress file with exactly one `complete` line -- ferrumd's SSE
/// handler tails that file and only closes the stream when it sees one.
/// `apply` and `rollback` write theirs inside `apply::run`/`rollback::run`
/// (which have real intermediate steps worth streaming); the remaining
/// kinds are single-shot, so they're instrumented here at the wrapper
/// level instead. Every one of these wrappers is ALSO the bare-CLI entry
/// point, where `Progress::open()` finds no FERRUM_JOB_ID and is a total
/// no-op -- so this changes nothing about running ferrum-apply by hand
/// over SSH.
fn run_preflight() -> i32 {
    let mut progress = progress::Progress::open();
    progress.event("preflight", "checking free space and snapshot subvolumes");
    match run_preflight_inner() {
        Ok(()) => {
            progress.complete("succeeded", "preflight passed");
            0
        }
        Err(e) => {
            eprintln!("preflight failed: {e}");
            progress.complete("failed", &e.to_string());
            1
        }
    }
}

fn run_preflight_inner() -> anyhow::Result<()> {
    let state_dir = std::env::var("FERRUM_STATE_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/state".to_string());
    let snapshot_dir = std::env::var("FERRUM_SNAPSHOT_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/snapshots".to_string());
    let min_free_gib: u64 = std::env::var("FERRUM_MIN_FREE_GIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let failure_marker_path = std::env::var("FERRUM_FAILURE_MARKER_PATH")
        .unwrap_or_else(|_| "/var/lib/ferrum/state-restore-failed".to_string());
    preflight::run(
        std::path::Path::new(&state_dir),
        std::path::Path::new(&snapshot_dir),
        min_free_gib,
        std::path::Path::new(&failure_marker_path),
    )
}

/// Everything `apply::run` needs, resolved from the environment ferrumd's
/// systemd unit sets.
///
/// Extracted from `run_apply` so the update commit reaches the apply
/// pipeline through the IDENTICAL configuration an ordinary apply uses.
/// R4's first criterion is that an update runs through the unmodified
/// `apply::run`; a second, independently-assembled `StorageConfig` would
/// satisfy that letter while breaking its point, and would be free to drift
/// -- a differing free-space threshold, a differing health-check timeout --
/// until an update behaved unlike an apply for reasons nobody chose.
///
/// # Returns
/// The storage, health-check and secrets configuration for one apply.
fn storage_from_env() -> apply::StorageConfig {
    apply::StorageConfig {
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
        failure_marker_path: std::env::var("FERRUM_FAILURE_MARKER_PATH")
            .unwrap_or_else(|_| "/var/lib/ferrum/state-restore-failed".to_string())
            .into(),
        health_check_timeout: std::time::Duration::from_secs(
            std::env::var("FERRUM_HEALTH_CHECK_TIMEOUT_SEC")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
        ),
        secrets_dir: std::env::var("FERRUM_SECRETS_DIR")
            .unwrap_or_else(|_| "/etc/ferrum/secrets".to_string())
            .into(),
        servarr_apps: std::env::var("FERRUM_SERVARR_APPS")
            .unwrap_or_else(|_| "sonarr,radarr,prowlarr".to_string())
            .split(',')
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .collect(),
        host_key_pub: std::env::var("FERRUM_HOST_KEY_PUB")
            .unwrap_or_else(|_| ferrum_secrets::DEFAULT_HOST_KEY_PUB.to_string())
            .into(),
        auth_enabled: std::env::var("FERRUM_AUTH_ENABLED")
            .map(|v| v == "1")
            .unwrap_or(false),
        authelia_state_dir: std::env::var("FERRUM_AUTHELIA_STATE_DIR")
            .unwrap_or_else(|_| "/var/lib/authelia-main".to_string())
            .into(),
        admin_email: std::env::var("FERRUM_ADMIN_EMAIL")
            .unwrap_or_default(),
        sabnzbd_state_dir: std::env::var("FERRUM_SABNZBD_STATE_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(std::path::PathBuf::from),
        sabnzbd_port: std::env::var("FERRUM_SABNZBD_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080),
        root_password_file: std::env::var("FERRUM_ROOT_PASSWORD_FILE")
            .unwrap_or_else(|_| secrets::DEFAULT_ROOT_PASSWORD_FILE.to_string())
            .into(),
        // False here and set by `run_update` alone, so the one shared
        // config this function exists to provide stays shared: an ordinary
        // apply must never mark its snapshot as an update's way back.
        update_pre_image: false,
    }
}

/// The flake reference every build in this process starts from.
///
/// One reader, shared by the apply and the update, for the reason
/// `storage_from_env` exists: two copies of this default could disagree,
/// and the one that disagreed would build a different host.
///
/// # Returns
/// `$FERRUM_FLAKE_REF`, or this crate's compiled-in default.
fn flake_ref_from_env() -> String {
    std::env::var("FERRUM_FLAKE_REF")
        .unwrap_or_else(|_| "/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel".to_string())
}

/// The journal directory, from the environment.
///
/// # Returns
/// `$FERRUM_JOURNAL_DIR`, or the compiled-in default. One reader, because
/// three call sites already resolved it independently and a fourth that
/// disagreed would read a different host's rollback bookkeeping.
fn journal_dir_from_env() -> std::path::PathBuf {
    std::env::var("FERRUM_JOURNAL_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/journal".to_string())
        .into()
}

/// How the pin on disk stands against the pin the running generation was
/// built from, as the three real reads answer it.
///
/// Split from `run_apply` so the decision itself stays testable: everything
/// this touches is a file or a symlink, and everything `pin_gate` does with
/// the result is pure.
///
/// # Arguments
/// * `flake_ref` - the reference the apply would build, e.g.
///   `/etc/ferrum#nixosConfigurations...`.
/// * `journal_dir` - ferrum's snapshot journal.
///
/// # Returns
/// The comparison. Every read that fails contributes `None` rather than an
/// error, so an unreadable lock or an unreadable journal degrades to
/// "unknown" -- which `pin_gate::decide` lets through. Failing an apply
/// because a bookkeeping file could not be read would be a far worse
/// outcome than the provenance going unrecorded.
fn pin_state_for_apply(flake_ref: &str, journal_dir: &std::path::Path) -> pin_gate::PinState {
    let (flake_dir, _) = update_check::split_flake_ref(flake_ref);
    let on_disk = pin::read(
        &std::path::Path::new(&flake_dir).join("flake.lock"),
        update_candidate::FERRUM_INPUT,
    );
    // The running closure, not the profile's own pointer -- `apply::run`
    // distrusts that pointer for the same reason (a partially-failed apply
    // can leave it naming a generation that was never activated), and the
    // two must agree about what "running" means or the gate would compare
    // the pin of a generation the host is not on.
    let running = std::fs::read_link("/run/current-system").ok();
    let recorded = running.and_then(|toplevel| {
        let entries = ferrum_state::journal::list(journal_dir).ok()?;
        ferrum_state::generations::built_pin_of(&toplevel.to_string_lossy(), &entries)
    });
    pin_gate::classify(on_disk, recorded)
}

/// `ferrum-apply apply`, gated on R8's pin comparison.
///
/// # Arguments
/// * `accept_pin_change` - the revision the operator acknowledged, if any.
///
/// # Returns
/// The process exit code: 1 when the gate refuses (before anything is built
/// or stopped), otherwise whatever the apply itself produced.
fn run_apply(accept_pin_change: Option<&str>) -> i32 {
    let flake_ref = flake_ref_from_env();
    let state = pin_state_for_apply(&flake_ref, &journal_dir_from_env());
    // The running generation's NUMBER is only needed to name it in the
    // refusal, so a host whose profile cannot be read is still gated -- it
    // just cannot say which generation. Nothing about the decision depends
    // on it.
    let generation = apply::current_generation().map(|(g, _)| g).unwrap_or(0);
    run_apply_gated(
        &state,
        generation,
        accept_pin_change,
        &mut progress::Progress::open(),
        || handle_apply_result(apply::run(&flake_ref, &storage_from_env())),
    )
}

/// The gate itself: refuse, or hand off to the apply.
///
/// Separated from `run_apply` for the reason `run_request` is separated
/// from `main`: the thing worth pinning is that a refused apply NEVER
/// reaches the builder, and that is only observable if the builder is a
/// value a test can hand in.
///
/// # Arguments
/// * `state` - the pin comparison.
/// * `generation` - the running generation, for the message.
/// * `accepted` - the revision the operator acknowledged, if any.
/// * `progress` - the job's progress file.
/// * `run` - the real apply. Called only when the gate lets it through, and
///   its exit code is returned unchanged.
///
/// # Returns
/// 1 on a refusal -- before anything is built, stopped, or snapshotted --
/// otherwise whatever `run` returned.
fn run_apply_gated(
    state: &pin_gate::PinState,
    generation: u32,
    accepted: Option<&str>,
    progress: &mut progress::Progress,
    run: impl FnOnce() -> i32,
) -> i32 {
    let pin_gate::Decision::Refuse(refusal) = pin_gate::decide(state, generation, accepted) else {
        return run();
    };
    // One event, two audiences, split on the FIRST ": " -- the same shape
    // `progress::complete` already writes and the same split the UI already
    // performs on it (`splitCompletion` in ui/app.js). The revision comes
    // first because the UI needs it verbatim to build the acknowledged
    // retry; the prose follows because the operator needs that and nothing
    // else.
    progress.event("pin-gate", &format!("{}: {}", refusal.accept_rev, refusal.message));
    progress.complete("failed", &refusal.message);
    eprintln!("apply refused: {}", refusal.message);
    1
}

/// The Nix profile directory, from the environment.
///
/// # Returns
/// `$FERRUM_PROFILES_DIR`, or the real `/nix/var/nix/profiles`. The same
/// variable ferrumd already resolves its generation list from, and
/// overridable here for the same reason every other path in this crate is:
/// so the behaviour can be exercised against a real directory.
fn profiles_dir_from_env() -> std::path::PathBuf {
    std::env::var("FERRUM_PROFILES_DIR")
        .unwrap_or_else(|_| "/nix/var/nix/profiles".to_string())
        .into()
}

/// What a rollback to `target` must say about the on-disk pin, if anything.
///
/// # Arguments
/// * `target` - the generation being rolled back to.
/// * `profiles_dir` - the Nix profile directory, where `system-<N>-link`
///   resolves the target's own closure.
/// * `journal_dir` - ferrum's snapshot journal.
/// * `flake_ref` - the reference a later apply would build from, which is
///   where the on-disk lock lives.
///
/// # Returns
/// The sentence, or `None` when the pins agree or either side is unknown.
/// Every read that fails contributes `None`: a rollback must not be made
/// harder by bookkeeping it cannot reach.
fn rollback_pin_notice(
    target: u32,
    profiles_dir: &std::path::Path,
    journal_dir: &std::path::Path,
    flake_ref: &str,
) -> Option<String> {
    let (flake_dir, _) = update_check::split_flake_ref(flake_ref);
    let on_disk = pin::read(
        &std::path::Path::new(&flake_dir).join("flake.lock"),
        update_candidate::FERRUM_INPUT,
    );
    let recorded = std::fs::read_link(profiles_dir.join(format!("system-{target}-link")))
        .ok()
        .and_then(|toplevel| {
            let entries = ferrum_state::journal::list(journal_dir).ok()?;
            ferrum_state::generations::built_pin_of(&toplevel.to_string_lossy(), &entries)
        });
    pin_gate::rollback_notice(&pin_gate::classify(on_disk, recorded), target)
}

fn run_rollback(to: u32) -> i32 {
    let journal_dir = std::env::var("FERRUM_JOURNAL_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/journal".to_string());
    let intent_path = std::env::var("FERRUM_ROLLBACK_INTENT_PATH")
        .unwrap_or_else(|_| "/var/lib/ferrum/rollback-intent.json".to_string());
    let snapshot_dir = std::env::var("FERRUM_SNAPSHOT_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/snapshots".to_string());
    let pin_notice = rollback_pin_notice(
        to,
        &profiles_dir_from_env(),
        std::path::Path::new(&journal_dir),
        &flake_ref_from_env(),
    );
    match rollback::run(
        to,
        std::path::Path::new(&journal_dir),
        std::path::Path::new(&intent_path),
        std::path::Path::new(&snapshot_dir),
        pin_notice.as_deref(),
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("rollback failed: {e}");
            1
        }
    }
}

fn run_restore_state() -> i32 {
    // Must not panic: an unresolvable device (e.g. a bind-mounted
    // state dir with no `device`) means NixOS omits this var
    // entirely. An empty string is handled as a real failure inside
    // restore_state::run's fail-closed flow, not here.
    let root_device = std::env::var("FERRUM_ROOT_DEVICE").unwrap_or_default();
    let intent_path = std::env::var("FERRUM_ROLLBACK_INTENT_PATH")
        .unwrap_or_else(|_| "/var/lib/ferrum/rollback-intent.json".to_string());
    let failure_marker_path = std::env::var("FERRUM_FAILURE_MARKER_PATH")
        .unwrap_or_else(|_| "/var/lib/ferrum/state-restore-failed".to_string());
    let storage = restore_state::StorageConfig {
        intent_path: intent_path.into(),
        result_path: "/var/lib/ferrum/rollback-result.json".into(),
        failure_marker_path: failure_marker_path.into(),
    };
    let mut progress = progress::Progress::open();
    progress.event("restore-state", "performing any pending state restore");
    // Whether there was anything to do at all, captured BEFORE the run:
    // restore_state::run removes the intent file on confirmed success, so
    // asking afterwards can't distinguish "ordinary boot, nothing pending"
    // from "a real restore that completed".
    let had_intent = storage.intent_path.exists();
    restore_state::run(&root_device, &storage);
    let (result, detail) = restore_state_outcome(&storage, had_intent);
    progress.complete(result, &detail);
    0 // always exits 0 -- see Global Constraints
}

/// The real outcome of a `restore-state` run, read back from the real
/// signal `restore_state::run` uses.
///
/// `restore_state::run` returns `()` on purpose -- a failed restore must
/// never fail the boot -- so it reports failure by leaving
/// `failure_marker_path` in place (that same marker is what
/// `ferrum-apps.target`'s ConditionPathExists uses to hold managed apps
/// down) and by writing `{"ok": false, ...}` to `result_path`. The marker
/// is therefore the authoritative signal, and this reads it rather than
/// assuming success: `RestoreState` is a real operator-triggerable job kind
/// over `POST /api/jobs`, and an SSE stream that always says "succeeded"
/// would tell an operator the box is fine while it is actually sitting with
/// apps held down by a failed restore.
///
/// A marker left over from an EARLIER boot's failure is deliberately still
/// reported as a failure here: apps really are being held down right now,
/// which is the thing the operator needs to know, and this run genuinely
/// did not clear it.
///
/// Fails closed on an unreadable marker (permission denied, an I/O error):
/// "I cannot tell" is reported as a failure, never as success.
fn restore_state_outcome(
    storage: &restore_state::StorageConfig,
    had_intent: bool,
) -> (&'static str, String) {
    let marker = &storage.failure_marker_path;
    match std::fs::read_to_string(marker) {
        Ok(reason) => {
            let reason = reason.trim();
            let reason = if reason.is_empty() { "no reason recorded" } else { reason };
            (
                "failed",
                format!(
                    "state restore failed: {reason} -- the failure marker at {} is holding \
                     managed apps down until it is cleared",
                    marker.display()
                ),
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if had_intent {
                (
                    "succeeded",
                    "pending state restore completed; the failure marker was cleared".to_string(),
                )
            } else {
                (
                    "succeeded",
                    "no state restore was pending; nothing to do".to_string(),
                )
            }
        }
        Err(e) => (
            "failed",
            format!(
                "could not read the state-restore failure marker at {}: {e} -- reporting \
                 failure rather than assuming the restore was fine",
                marker.display()
            ),
        ),
    }
}

/// Shells out to `nix eval --json` against the real flake to compute
/// what a schema migration would produce, WITHOUT writing anything --
/// this is a preview, matching this plan's own Global Constraint that
/// the preview step must be provably read-only. Derives the flake
/// directory from the same FERRUM_FLAKE_REF env var `run_apply()`
/// already reads (splitting off the `#attr` suffix), so a deployment
/// or test that points FERRUM_FLAKE_REF at a non-default flake gets
/// the same flake here -- never a second, independently-configured
/// path that could drift from it. Evaluates `config.ferrum.schemaVersion`
/// (cheap: a plain int) rather than `config.system.build.toplevel`
/// (expensive: forces a full build).
fn run_preview_migration() -> i32 {
    let settings_path = std::env::var("FERRUM_SETTINGS_PATH")
        .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
    let flake_ref = std::env::var("FERRUM_FLAKE_REF").unwrap_or_else(|_| {
        "/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel".to_string()
    });
    let flake_dir = flake_ref.split('#').next().unwrap_or(&flake_ref);

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

    if target_version < current_version {
        eprintln!(
            "preview-migration: warning: on-disk settings.json (schemaVersion {current_version}) is newer than this ferrum's module tree (schemaVersion {target_version}) -- no migration will run"
        );
    }
    let summary = serde_json::json!({
        "current_version": current_version,
        "target_version": target_version,
        "would_migrate": target_version > current_version,
    });
    println!("{summary}");
    0
}

/// Decides a check's job outcome from what the check itself produced.
///
/// Split out so the one case that must never be silent -- the read-only
/// guarantee having been broken -- is testable without a real `nix`.
///
/// # Arguments
/// * `violations` - one message per protected file the check modified.
/// * `written` - where the report document landed, or why it could not be
///   written.
///
/// # Returns
/// `(result, detail, exit_code)` for the terminal progress line and the
/// process exit.
fn check_update_outcome(
    violations: &[String],
    written: Result<std::path::PathBuf, String>,
    summary: &str,
) -> (&'static str, String, i32) {
    // Checked before the write outcome: a check that moved a pin is a
    // failure whether or not it also managed to file a report about it.
    if !violations.is_empty() {
        return ("failed", violations.join("; "), 1);
    }
    match written {
        Ok(path) => ("succeeded", format!("{summary} (report: {})", path.display()), 0),
        Err(e) => (
            "failed",
            format!("the check ran but its report could not be written: {e}"),
            1,
        ),
    }
}

/// Everything the update check reads out of the environment, resolved once.
///
/// Split from the run below so that the run is a function of its inputs and
/// nothing else. The composition it performs -- capture the tripwire, build
/// the report, hand the tripwire's real output to the outcome, publish,
/// exit -- is the part with no second chance if it is wrong, and it was not
/// reachable from a test while it read the environment and constructed a
/// `RealRunner` inline.
struct CheckUpdateJob {
    /// The flake directory, e.g. `/etc/ferrum`.
    flake_dir: String,
    /// The configuration attribute path up to and including `.config`.
    config_attr: String,
    /// The host's `settings.json`.
    settings_path: std::path::PathBuf,
    /// The two files the read-only guarantee is measured against.
    flake_nix: std::path::PathBuf,
    flake_lock: std::path::PathBuf,
    /// ferrum's snapshot journal, where each apply recorded the pin it
    /// built from (R8). Read, never written, like everything else here.
    journal_dir: std::path::PathBuf,
    /// The symlink naming the closure this host is RUNNING. Overridable
    /// so the whole provenance join is exercised against real files.
    running_system: std::path::PathBuf,
    /// Where the report document is published.
    report_dir: std::path::PathBuf,
    /// The report's file name, from `$FERRUM_JOB_ID`.
    report_file: String,
    /// The host clock, as seconds since the epoch.
    now: u64,
}

impl CheckUpdateJob {
    /// Resolve the job from the environment ferrumd sets.
    ///
    /// # Returns
    /// The paths and identifiers the run below needs.
    fn from_env() -> Self {
        let flake_ref = std::env::var("FERRUM_FLAKE_REF").unwrap_or_else(|_| {
            "/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel".to_string()
        });
        let (flake_dir, config_attr) = update_check::split_flake_ref(&flake_ref);
        let settings_path = std::env::var("FERRUM_SETTINGS_PATH")
            .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
        let job_id = std::env::var("FERRUM_JOB_ID").ok();
        Self {
            flake_nix: std::path::Path::new(&flake_dir).join("flake.nix"),
            flake_lock: std::path::Path::new(&flake_dir).join("flake.lock"),
            settings_path: settings_path.into(),
            journal_dir: journal_dir_from_env(),
            running_system: std::env::var("FERRUM_RUNNING_SYSTEM")
                .unwrap_or_else(|_| "/run/current-system".to_string())
                .into(),
            report_dir: update_check::report_dir(),
            report_file: update_check::report_file_name(job_id.as_deref()),
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            flake_dir,
            config_attr,
        }
    }
}

/// Runs the read-only update check and leaves its report where ferrumd can
/// read it.
///
/// Instrumented through `progress::Progress` -- unlike
/// `run_preview_migration`, which is CLI-only -- because this one is
/// dispatched as a job and `GET /api/jobs` renders its stream.
///
/// # Arguments
/// * `job` - the resolved paths and clock.
/// * `runner` - the subprocess seam, so a test can drive the whole
///   composition without a real `nix` or `git`.
/// * `progress` - the job's event stream.
///
/// # Returns
/// A process exit code: 0 when a report was produced and written, 1 when it
/// could not be, or when the read-only guarantee was broken.
fn run_check_update_job(
    job: &CheckUpdateJob,
    runner: &dyn update_check::CommandRunner,
    progress: &mut progress::Progress,
) -> i32 {
    // Captured BEFORE the first subprocess, released after the last: the
    // window this covers is the whole check.
    let guard = update_check::ReadOnlyGuard::capture(&[&job.flake_nix, &job.flake_lock]);
    progress.event(
        "check-update",
        "reading this host's resolved configuration -- neither flake.nix nor flake.lock is \
         written",
    );

    let inputs = update_check::CheckInputs {
        flake_dir: &job.flake_dir,
        config_attr: &job.config_attr,
        settings_path: &job.settings_path,
        flake_nix: &job.flake_nix,
        flake_lock: &job.flake_lock,
        journal_dir: &job.journal_dir,
        running_system: &job.running_system,
        now: job.now,
    };
    let mut report = update_check::build_report(&inputs, runner);

    let violations = guard.violations();
    report.warnings.extend(violations.iter().cloned());

    let written = update_check::write_report(&job.report_dir, &job.report_file, &report)
        .map_err(|e| e.to_string());

    // stdout carries the whole document, so a bare `ferrum-apply
    // check-update` over SSH is useful on its own -- the same way
    // `preview-migration` prints its summary. Nothing in it is a secret:
    // `update_candidate` strips userinfo at the parse precisely because
    // this line, and the journal behind it, are below the trust level of
    // the root-only file the URL came from.
    match serde_json::to_string(&report) {
        Ok(body) => println!("{body}"),
        Err(e) => eprintln!("check-update: could not serialize the report: {e}"),
    }

    let summary = update_check::summary_line(&report);
    let (result, detail, code) = check_update_outcome(&violations, written, &summary);
    if code != 0 {
        eprintln!("check-update failed: {detail}");
    }
    progress.complete(result, &detail);
    code
}

/// The environment-reading wrapper the CLI and the dispatcher both call.
///
/// # Returns
/// The process exit code from `run_check_update_job`.
fn run_check_update() -> i32 {
    let mut progress = progress::Progress::open();
    run_check_update_job(
        &CheckUpdateJob::from_env(),
        &update_check::RealRunner,
        &mut progress,
    )
}

/// Everything the update commit reads out of the environment, resolved once.
///
/// Split from the run below for the reason `CheckUpdateJob` was: the
/// composition it performs -- refuse a dirty tree, resolve, advance, apply,
/// undo on failure -- is the part with no second chance if it is wrong, and
/// it is not reachable from a test while it reads the environment.
struct UpdateJob {
    /// The reference `apply::run` will be given, unchanged.
    flake_ref: String,
    /// The flake directory, e.g. `/etc/ferrum`.
    flake_dir: String,
    /// The file that must stay byte-identical.
    flake_nix: std::path::PathBuf,
    /// The one file this job writes.
    flake_lock: std::path::PathBuf,
    /// The host clock, as seconds since the epoch.
    now: u64,
}

impl UpdateJob {
    /// Resolve the job from the environment ferrumd sets.
    ///
    /// # Returns
    /// The paths and clock the run below needs.
    fn from_env() -> Self {
        let flake_ref = flake_ref_from_env();
        let (flake_dir, _) = update_check::split_flake_ref(&flake_ref);
        Self {
            flake_nix: std::path::Path::new(&flake_dir).join("flake.nix"),
            flake_lock: std::path::Path::new(&flake_dir).join("flake.lock"),
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            flake_dir,
            flake_ref,
        }
    }
}

/// What an update's apply did to the generation sequence.
///
/// The distinction `apply::run` does not draw and R4's last edge case
/// requires: when the advanced pin builds a closure identical to the one
/// already running, `apply::run` returns early after a health check -- no
/// preflight, no snapshot, no journal entry, no new generation -- and
/// reports `Succeeded`. Telling the operator "applied" there would be a
/// lie in a status line. This is read from the generation NUMBER before and
/// after rather than from the result, because the number is the thing that
/// did or did not move, and reading it requires no change to `apply::run`.
#[derive(Debug, PartialEq, Eq)]
enum Produced {
    /// A new generation exists.
    Generation(u32),
    /// The build produced the closure already running.
    NoChange,
    /// The generation could not be read on one side or the other, so
    /// neither claim can be made. Reported as itself, never as "no change".
    Unknown,
}

/// Classify what the apply produced from the generation number either side
/// of it.
///
/// # Arguments
/// * `before` - the system generation before the apply, if it could be read.
/// * `after` - the system generation after it, if it could be read.
///
/// # Returns
/// The new generation, `NoChange` when the number did not move, or
/// `Unknown` when either side is missing.
fn produced(before: Option<u32>, after: Option<u32>) -> Produced {
    match (before, after) {
        (Some(b), Some(a)) if a != b => Produced::Generation(a),
        (Some(_), Some(_)) => Produced::NoChange,
        _ => Produced::Unknown,
    }
}

/// The operator-facing sentence for one update outcome.
///
/// # Arguments
/// * `produced` - what the apply did to the generation sequence.
/// * `to` - the revision the pin was advanced to.
///
/// # Returns
/// The `detail` of the job's terminal progress line, which is what the
/// Updates view renders.
fn update_detail(produced: &Produced, to: &str) -> String {
    let rev = update_candidate::short_rev(to);
    match produced {
        Produced::Generation(n) => {
            format!("updated to {rev} as generation {n}")
        }
        // The exact words R4's last edge case requires. "Nothing to apply"
        // rather than "applied": no generation was created, so there is
        // also nothing new to roll back to.
        Produced::NoChange => format!(
            "no change — nothing to apply. The pin now records {rev}, and it builds the system \
             this host is already running, so no new generation was created"
        ),
        Produced::Unknown => format!(
            "the pin now records {rev} and the apply finished, but this host's generation \
             number could not be read either before or after, so whether a new generation was \
             created is unknown -- check the Generations view"
        ),
    }
}

/// Advance the pin and apply it, as one operator action.
///
/// One action rather than two staged steps (Open Question 5's resolution):
/// a lock that has been advanced but not applied is exactly the drift R8
/// exists to prevent -- a later, unrelated settings apply would pick the new
/// versions up with the operator never having reviewed them.
///
/// # Arguments
/// * `job` - the resolved paths and clock.
/// * `runner` - the subprocess seam, so a test can drive the whole
///   composition without a real `nix` or `git`.
/// * `progress` - the job's event stream.
/// * `apply` - the apply pipeline. Injected so the composition is testable;
///   production passes the real, unmodified `apply::run`.
/// * `generation` - reads the system generation number, for the no-change
///   case above.
///
/// # Returns
/// A process exit code: 0 when the update was applied (or when there was
/// nothing to apply), 3 when the resulting apply degraded, 1 when anything
/// was refused or failed.
fn run_update_job(
    job: &UpdateJob,
    runner: &dyn update_check::CommandRunner,
    progress: &mut progress::Progress,
    apply_fn: impl FnOnce(&str) -> anyhow::Result<apply::ApplyResult>,
    generation: impl Fn() -> Option<u32>,
) -> i32 {
    progress.event(
        "update",
        &format!("checking that {} has no uncommitted changes", job.flake_dir),
    );
    if let Err(e) = update_apply::require_clean_tree(runner, &job.flake_dir) {
        progress.complete("failed", &e);
        eprintln!("update: {e}");
        return 1;
    }

    progress.event("update", "resolving the candidate revision");
    let outcome = update_candidate::resolve(runner, &job.flake_nix, &job.flake_lock, job.now);
    let report = &outcome.report;
    let rev = match report.state {
        update_check::CandidateState::UpdateAvailable => match report.rev.as_deref() {
            Some(r) => r.to_string(),
            None => {
                let detail =
                    "an update was found but no revision came back with it, so there is \
                     nothing this host can be advanced to"
                        .to_string();
                progress.complete("failed", &detail);
                eprintln!("update: {detail}");
                return 1;
            }
        },
        // Not a failure, and deliberately not phrased as one: the host is
        // where it should be and nothing was written.
        update_check::CandidateState::UpToDate => {
            let detail = format!(
                "already at the newest release this host tracks ({}) — nothing to apply",
                update_candidate::short_rev(report.rev.as_deref().unwrap_or("unknown"))
            );
            progress.complete("succeeded", &detail);
            println!("{detail}");
            return 0;
        }
        // Monotonicity, enforced here and not only at discovery (DA-1):
        // discovery and this job resolve independently and minutes apart.
        // `OrderUnknown` is refused for the same reason `NotNewer` is --
        // "we cannot tell whether this is newer" must never be treated as
        // "it is".
        other => {
            let detail = format!(
                "refusing to update: {}{}",
                match other {
                    update_check::CandidateState::NotNewer =>
                        "the tracked reference points at a revision that is not newer than the \
                         one this host runs",
                    update_check::CandidateState::OrderUnknown =>
                        "ferrum could not establish that the candidate is newer than what this \
                         host runs",
                    _ => "the update check failed",
                },
                report
                    .error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            );
            progress.complete("failed", &detail);
            eprintln!("update: {detail}");
            return 1;
        }
    };

    progress.event(
        "update",
        &format!(
            "advancing the ferrum pin to {} -- flake.lock only",
            update_candidate::short_rev(&rev)
        ),
    );
    let advanced = match update_apply::advance(
        runner,
        &job.flake_dir,
        &job.flake_nix,
        &job.flake_lock,
        &rev,
    ) {
        Ok(a) => a,
        Err(e) => {
            progress.complete("failed", &e);
            eprintln!("update: {e}");
            return 1;
        }
    };

    // From here on this is an ordinary apply. Not a copy of one, not a
    // variant of one: the same function, the same configuration, the same
    // Succeeded/Degraded/Failed vocabulary, and therefore the same rollback
    // guarantee. R4's first criterion is that this feature does not fork,
    // duplicate, or branch `apply::run`, and the way that is kept true is
    // that there is nothing update-shaped on the other side of this call.
    let before = generation();
    let result = apply_fn(&job.flake_ref);
    let after = generation();

    // Used by the `Failed` arm only. A build that failed at the candidate
    // pin leaves an advanced lock that the next unrelated settings apply
    // would silently build from -- the exact drift R8 names. A DEGRADED
    // apply is not undone: that host did switch, and reverting the pin
    // under a running generation would make the lock disagree with what is
    // actually installed.
    let undo = |why: String| undo_pin(job, &advanced.previous_lock, why);

    let (name, detail, code) = match result {
        Ok(apply::ApplyResult::Succeeded) => {
            let p = produced(before, after);
            ("succeeded", update_detail(&p, &advanced.to.rev), 0)
        }
        Ok(apply::ApplyResult::Degraded(reason)) => (
            "degraded",
            format!(
                "updated to {}, but: {reason}",
                update_candidate::short_rev(&advanced.to.rev)
            ),
            3,
        ),
        Ok(apply::ApplyResult::Failed(reason)) => (
            "failed",
            undo(format!("the update could not be applied: {reason}")),
            1,
        ),
        // NOT undone, unlike `Failed` above, and the difference is not an
        // oversight. `ApplyResult::Failed` is a classified verdict from a
        // pipeline that got far enough to classify one; an `Err` is
        // `apply::run` giving up part-way, and it can be raised AFTER
        // `nix-env --set` and the switch ("apply failed mid-sequence"). So
        // "nothing switched" is exactly what cannot be assumed here, and
        // putting the pin back under a system that may already be running
        // the new closure would make flake.lock name a revision the host is
        // not on -- the same disagreement, pointed the other way. The one
        // honest move left is to say so and let the operator look.
        Err(e) => (
            "failed",
            format!(
                "the update could not be applied: {e}. The pin was already advanced to {}, and \
                 whether the switch happened is not knowable from here -- it has deliberately \
                 NOT been put back. Check the Generations view and `git -C {} diff flake.lock` \
                 before applying anything else",
                update_candidate::short_rev(&advanced.to.rev),
                job.flake_dir
            ),
            1,
        ),
    };
    if code == 0 {
        println!("{detail}");
    } else {
        eprintln!("update {name}: {detail}");
    }
    progress.complete(name, &detail);
    code
}

/// Put the pin back after an apply that classified itself as failed, and
/// say so.
///
/// Reached only from `ApplyResult::Failed`, which `apply::run` returns from
/// the build step and from a switch it classified — never from a sequence it
/// abandoned mid-way (see the `Err` arm at the call site). An advanced lock
/// under an unchanged running generation is the drift R8 exists to prevent:
/// the next unrelated settings apply would build from it, with no preview
/// and no confirmation.
///
/// # Arguments
/// * `job` - the paths, for the message's `git -C` hint.
/// * `previous` - the lock's bytes before the advance.
/// * `why` - what failed, in the words of whatever failed.
///
/// # Returns
/// The operator-facing detail, saying both what went wrong and what state
/// the pin is now in -- including, loudly, the case where the undo itself
/// failed, which is the only outcome here an operator must act on by hand.
fn undo_pin(job: &UpdateJob, previous: &[u8], why: String) -> String {
    match update_apply::restore(&job.flake_lock, previous) {
        Ok(()) => format!(
            "{why}. The pin has been put back where it was, so nothing else will build from it"
        ),
        Err(e) => format!(
            "{why}. WORSE: the pin could not be put back ({e}), so this host's flake.lock now \
             names a revision it is not running. Check `git -C {} diff flake.lock` before \
             applying anything else",
            job.flake_dir
        ),
    }
}

/// The environment-reading wrapper the CLI and the dispatcher both call.
///
/// # Returns
/// The process exit code from `run_update_job`.
/// `ferrum-apply confirm-update`: release the snapshots an unconfirmed
/// update was holding back from `gc`.
///
/// # Returns
/// 0 on success, including when there was nothing to release -- a host that
/// has never updated, or one confirmed twice, is not a failure. 1 when the
/// journal could not be swept, naming the directory: a partial sweep leaves
/// the remaining entries still protected, which is the safe direction, but
/// the operator needs to know the release did not finish.
fn run_confirm_update() -> i32 {
    let journal_dir = journal_dir_from_env();
    let mut progress = progress::Progress::open();
    match ferrum_state::journal::clear_update_marks(&journal_dir) {
        Ok(0) => {
            progress.complete(
                "succeeded",
                "nothing to confirm: no snapshot was being held back for an update",
            );
            0
        }
        Ok(n) => {
            progress.complete(
                "succeeded",
                &format!(
                    "{n} snapshot(s) released to ordinary retention -- this update is no longer \
                     holding anything back from gc"
                ),
            );
            0
        }
        Err(e) => {
            let detail = format!(
                "could not release the held snapshots in {}: {e}. Any entry still marked is \
                 still protected, so nothing has been lost",
                journal_dir.display()
            );
            eprintln!("confirm-update: {detail}");
            progress.complete("failed", &detail);
            1
        }
    }
}

fn run_update() -> i32 {
    let mut progress = progress::Progress::open();
    let job = UpdateJob::from_env();
    // The one deliberate difference from an ordinary apply's configuration,
    // and it changes nothing about what gets built: the snapshot this apply
    // takes is the host as it was BEFORE the pin moved, so it is the way
    // back from a bad update and `gc` must not prune it on the tenth
    // subsequent apply. Cleared again by `confirm-update`.
    let storage = apply::StorageConfig { update_pre_image: true, ..storage_from_env() };
    run_update_job(
        &job,
        &update_check::RealRunner,
        &mut progress,
        |flake_ref| apply::run(flake_ref, &storage),
        || apply::current_generation().ok().map(|(g, _)| g),
    )
}

/// A real GC pass: prunes state snapshots beyond `ferrum.storage.keepGenerations`.
///
/// Was a stub returning exit 1 until 2026-09-15, while
/// `ferrum.storage.keepGenerations` sat in options.nix and
/// settings-schema.json with no consumer anywhere -- so an operator could
/// set a retention policy that nothing enforced, and snapshots accumulated
/// for the life of the host. See gc.rs's own header for why that matters
/// more than it sounds.
/// Encrypts an operator-supplied secret read from stdin.
///
/// Deliberately does NOT go through `progress::Progress`: that file is the
/// job stream ferrumd renders, and this subcommand is invoked directly over
/// SSH by the installer, never dispatched as a ferrumd job (it is absent
/// from `request::Request` for the same reason). Writing a job file here
/// would fabricate an entry for work the daemon never asked for.
///
/// Returns 0 on success -- including the idempotent "already exists" path,
/// so a resumed install does not fail at this step.
fn run_put_secret(name: &str, replace: bool) -> i32 {
    let secrets_dir: std::path::PathBuf = std::env::var("FERRUM_SECRETS_DIR")
        .unwrap_or_else(|_| "/etc/ferrum/secrets".to_string())
        .into();
    let host_key_pub: std::path::PathBuf = std::env::var("FERRUM_HOST_KEY_PUB")
        .unwrap_or_else(|_| ferrum_secrets::DEFAULT_HOST_KEY_PUB.to_string())
        .into();

    match put_secret::run(&secrets_dir, &host_key_pub, name, replace) {
        Ok(put_secret::Outcome::Wrote) => {
            println!("put-secret: wrote {}", secrets_dir.join(format!("{name}.sops")).display());
            0
        }
        Ok(put_secret::Outcome::Replaced) => {
            println!("put-secret: replaced {}", secrets_dir.join(format!("{name}.sops")).display());
            0
        }
        Ok(put_secret::Outcome::Unchanged) => {
            println!(
                "put-secret: {} already exists, left unchanged (pass --replace to overwrite)",
                secrets_dir.join(format!("{name}.sops")).display()
            );
            0
        }
        Err(e) => {
            eprintln!("put-secret: {e}");
            1
        }
    }
}

/// Reconciles this host's DNS records against Cloudflare, then records that
/// it did (A8).
///
/// Reads only the state directory from the environment, the same way every
/// other subcommand here does. The credential is never read here: it comes
/// from the path the document names, inside `dns_reconcile`, so nothing
/// about it passes through argv or this function.
fn run_reconcile_dns(config: &std::path::Path) -> i32 {
    let state_dir = std::path::PathBuf::from(
        std::env::var("FERRUM_STATE_DIR").unwrap_or_else(|_| "/var/lib/ferrum/state".to_string()),
    );
    let marker = state_dir.join("dns-updater-last-success");
    let outcome = dns_reconcile::run(
        config,
        &dns_reconcile::cloudflare_client,
        &dns_reconcile::authoritative_verifier,
        &dns_reconcile::production_address_policy(&state_dir),
    );
    reconcile_dns_exit(outcome, &marker, std::time::SystemTime::now())
}

/// Turns a reconcile outcome into output and an exit code.
///
/// Exit codes follow `handle_apply_result`'s convention so a unit or future
/// automation can tell the cases apart without parsing text: **0** clean,
/// **3** reconciled but something is wrong, **1** could not reconcile at
/// all, **4** this host's public address was discovered and deliberately
/// REFUSED.
///
/// 4 is its own code rather than another 1, and F1/R1 asks for exactly that.
/// "Ferrum could not reach the internet" and "the internet disagreed with
/// itself about where this host is" send an operator to two different
/// places, and both must be distinguishable from exit 0, which here means
/// "looked, and there was nothing to change". The defect this closes is the
/// three of them having been indistinguishable -- silence -- for six weeks.
///
/// The last-success marker is written only on a clean cycle, and a cycle
/// with nothing to do counts as clean. Its *age* is the signal A8 asks for:
/// a timer that has been erroring for six weeks is, from outside,
/// indistinguishable from one that has never had anything to do -- unless
/// something records the difference. `ferrum-apply apply`'s in-process
/// reconcile deliberately does not write it, so the file keeps meaning "the
/// scheduled updater ran and was happy" rather than "something, at some
/// point, looked".
///
/// # Arguments
/// * `outcome` - what `dns_reconcile::run` returned.
/// * `marker` - where the last-success timestamp lives.
/// * `now` - the timestamp to record.
fn reconcile_dns_exit(
    outcome: Result<Option<dns_reconcile::ReconcileReport>, dns_reconcile::ReconcileError>,
    marker: &std::path::Path,
    now: std::time::SystemTime,
) -> i32 {
    let report = match outcome {
        Ok(Some(report)) => report,
        Ok(None) => {
            println!("reconcile-dns: DNS record management is disabled on this host");
            return 0;
        }
        Err(e) => {
            eprintln!("reconcile-dns: {e}");
            // The marker is deliberately NOT written on either branch: a
            // refusal is not a clean cycle, and letting its age keep
            // advancing would hide a host that has been refusing to publish
            // since its ISP put it behind CGNAT.
            return if e.is_discovery_refusal() { 4 } else { 1 };
        }
    };

    println!("{}", report.full_summary());
    if let Some(failures) = report.failure_summary() {
        eprintln!("reconcile-dns: {failures}");
        return 3;
    }
    // Reconciliation itself succeeded, so this is not a failed cycle -- but
    // an unwritten marker means the next observer cannot tell a working
    // updater from a silent one, which is the entire point of the file. Say
    // so rather than exiting 0 in silence.
    if let Err(e) = dns_reconcile::record_last_success(marker, now) {
        eprintln!(
            "reconcile-dns: records are correct, but the last-success marker at {} could not be written: {e}",
            marker.display()
        );
        return 3;
    }
    if !report.scheduled {
        println!(
            "reconcile-dns: scheduled re-checks are off -- these records will not be corrected \
             automatically if this host's public address changes"
        );
    }
    0
}

fn run_gc() -> i32 {
    let mut progress = progress::Progress::open();
    match run_gc_inner(&mut progress) {
        Ok(pruned) => {
            let detail = format!("pruned {pruned} snapshot(s)");
            println!("gc: {detail}");
            progress.complete("succeeded", &detail);
            0
        }
        Err(e) => {
            eprintln!("gc failed: {e}");
            progress.complete("failed", &e.to_string());
            1
        }
    }
}

fn run_gc_inner(progress: &mut progress::Progress) -> anyhow::Result<usize> {
    let snapshot_dir = std::env::var("FERRUM_SNAPSHOT_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/snapshots".to_string());
    let journal_dir = std::env::var("FERRUM_JOURNAL_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/journal".to_string());
    // Matches ferrum.storage.keepGenerations' own default in
    // modules/core/options.nix. The module wires the real value through
    // modules/core/overlays.nix, so this fallback only applies to a
    // ferrum-apply invoked outside a ferrum host.
    let keep_generations: usize = std::env::var("FERRUM_KEEP_GENERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    // Read from the live system, not from the journal: the running
    // generation is what rule 2 in gc::plan protects, and it is only
    // knowable from /run/current-system. A failure here must abort the
    // whole run rather than defaulting to "no generation is current" --
    // that would drop the protection and let the running generation's own
    // snapshot be pruned.
    let (current, _) = apply::current_generation()?;

    gc::run(
        std::path::Path::new(&snapshot_dir),
        std::path::Path::new(&journal_dir),
        keep_generations,
        current,
        progress,
    )
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Preflight => run_preflight(),
        Command::Apply { accept_pin_change } => run_apply(accept_pin_change.as_deref()),
        Command::Rollback { to } => run_rollback(to),
        Command::RestoreState => run_restore_state(),
        Command::Gc => run_gc(),
        Command::PreviewMigration => run_preview_migration(),
        Command::CheckUpdate => run_check_update(),
        Command::Update => run_update(),
        Command::ConfirmUpdate => run_confirm_update(),
        Command::ReconcileDns { config } => run_reconcile_dns(&config),
        Command::PutSecret { name, replace } => run_put_secret(&name, replace),
        Command::RunRequest { path } => match request::read_request(&path) {
            Ok(req) => run_request(req, &mut progress::Progress::open(), |req| match req {
                request::Request::Preflight => run_preflight(),
                request::Request::Apply { accept_pin_change } => {
                    run_apply(accept_pin_change.as_deref())
                }
                request::Request::Rollback { to } => run_rollback(to),
                request::Request::RestoreState => run_restore_state(),
                request::Request::Gc => run_gc(),
                request::Request::CheckUpdate => run_check_update(),
                request::Request::Update => run_update(),
                request::Request::ConfirmUpdate => run_confirm_update(),
            }),
            Err(e) => {
                eprintln!("run-request: {e}");
                progress::Progress::open().complete("failed", &e.to_string());
                1
            }
        },
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    mod reconcile_dns {
        use super::*;
        use crate::dns_reconcile::{Operation, ReconcileError, ReconcileReport, RecordReport};

        fn report(records: Vec<RecordReport>, scheduled: bool) -> ReconcileReport {
            ReconcileReport { records, scheduled }
        }

        fn clean_record() -> RecordReport {
            RecordReport {
                name: "auth.example.com".to_string(),
                operation: Operation::Create,
                failure: None,
                note: None,
            }
        }

        fn failed_record() -> RecordReport {
            RecordReport {
                name: "plex.example.com".to_string(),
                operation: Operation::Create,
                failure: Some("Cloudflare refused the request".to_string()),
                note: None,
            }
        }

        #[test]
        fn a_clean_cycle_exits_zero_and_leaves_a_timestamp_behind() {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("state").join("dns-updater-last-success");
            let code = reconcile_dns_exit(
                Ok(Some(report(vec![clean_record()], true))),
                &marker,
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_770_000_000),
            );
            assert_eq!(code, 0);
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "1770000000\n");
        }

        /// A cycle with nothing to do is still a cycle that proved the
        /// records are right, so it must refresh the marker -- otherwise the
        /// file ages out on a host where nothing is wrong.
        #[test]
        fn a_no_op_cycle_still_refreshes_the_marker() {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("dns-updater-last-success");
            assert_eq!(
                reconcile_dns_exit(
                    Ok(Some(report(Vec::new(), true))),
                    &marker,
                    std::time::SystemTime::now()
                ),
                0
            );
            assert!(marker.exists());
        }

        /// The marker must not claim a healthy cycle that did not happen: a
        /// failed record is exactly when a stale timestamp would be read as
        /// "the updater is fine".
        ///
        /// Mutation check: write the marker before checking
        /// `failure_summary()` and this fails.
        #[test]
        fn a_failed_record_exits_three_and_writes_no_timestamp() {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("dns-updater-last-success");
            let code = reconcile_dns_exit(
                Ok(Some(report(vec![clean_record(), failed_record()], true))),
                &marker,
                std::time::SystemTime::now(),
            );
            assert_eq!(code, 3, "a partial result is a reported failure");
            assert!(
                !marker.exists(),
                "a failed cycle must not leave a marker claiming success"
            );
        }

        /// A run that could not start at all is distinct from one that ran
        /// and found problems, so the exit code distinguishes them.
        #[test]
        fn a_run_that_could_not_start_exits_one_and_writes_no_timestamp() {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("dns-updater-last-success");
            let code = reconcile_dns_exit(
                Err(ReconcileError::NoCredentialConfigured),
                &marker,
                std::time::SystemTime::now(),
            );
            assert_eq!(code, 1);
            assert!(!marker.exists());
        }

        #[test]
        fn a_host_that_does_not_manage_dns_exits_zero_without_a_timestamp() {
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("dns-updater-last-success");
            assert_eq!(
                reconcile_dns_exit(Ok(None), &marker, std::time::SystemTime::now()),
                0
            );
            assert!(
                !marker.exists(),
                "a host that reconciles nothing has not proved anything about its records"
            );
        }

        /// F1/R1. Refusing an address and failing to find one are different
        /// facts that send an operator to different places, and both must be
        /// distinguishable from exit 0's "nothing to change". The defect
        /// this closes is all three having been the same silence.
        #[test]
        fn a_refused_address_exits_four_and_a_failed_lookup_exits_one() {
            use ferrum_dns::public_ip::DiscoveryError;
            let dir = tempfile::tempdir().unwrap();
            let marker = dir.path().join("dns-updater-last-success");

            let refused = reconcile_dns_exit(
                Err(ReconcileError::Discovery(DiscoveryError::Disagreement {
                    answers: vec![
                        ("alpha".to_string(), "142.180.179.64".parse().unwrap()),
                        ("beta".to_string(), "184.148.39.165".parse().unwrap()),
                    ],
                })),
                &marker,
                std::time::SystemTime::now(),
            );
            assert_eq!(refused, 4, "a refusal has its own exit code");
            assert!(
                !marker.exists(),
                "a refusal is not a clean cycle -- letting the marker age on \
                 would hide a host that has refused to publish for weeks"
            );

            let unreachable = reconcile_dns_exit(
                Err(ReconcileError::Discovery(
                    DiscoveryError::NotEnoughOperators {
                        answered: Vec::new(),
                        failures: vec!["alpha: timed out".to_string()],
                    },
                )),
                &marker,
                std::time::SystemTime::now(),
            );
            assert_eq!(unreachable, 1, "not finding out is the ordinary failure");
            assert!(!marker.exists());
        }
    }
    use clap::Parser;

    /// The `started` line must be the FIRST line of a dispatched job's file.
    /// `GET /api/jobs` reads only the first line to recover a job's kind, so
    /// if a subcommand's own progress landed ahead of it the kind would be
    /// reported as null for every job.
    ///
    /// Uses `Progress::to_path` rather than `FERRUM_JOB_ID`/`FERRUM_JOBS_DIR`:
    /// those are process-wide, and progress.rs's own env test runs in this
    /// same test binary, so racing it would make this flaky.
    #[test]
    fn a_dispatched_jobs_started_line_comes_before_the_subcommands_own_progress() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("job.jsonl");
        let mut progress = progress::Progress::to_path(&path);

        let code = run_request(request::Request::Gc, &mut progress, |req| {
            // Stand-in for a real subcommand writing its own progress.
            progress::Progress::to_path(&path).event("pruning", &format!("ran {}", req.kind()));
            0
        });
        assert_eq!(code, 0, "the runner's exit code must pass through unchanged");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2, "expected exactly the started line then the subcommand's: {content}");

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "started", "the FIRST line must be the started event");
        assert_eq!(first["detail"], "gc", "and it must name the request's own kind");

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "pruning", "the subcommand's progress follows it");
    }

    /// The read-only check is dispatched through the same mechanism as
    /// every other capability (R3's second criterion), which means its
    /// `started` line has to carry its own kind -- otherwise `GET
    /// /api/jobs` reports a running check as a job of unknown kind, and the
    /// UI has nothing to reattach to.
    #[test]
    fn a_dispatched_check_update_announces_its_own_kind_before_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("job.jsonl");
        let mut progress = progress::Progress::to_path(&path);

        let code = run_request(request::Request::CheckUpdate, &mut progress, |req| {
            progress::Progress::to_path(&path).event("check-update", &format!("ran {}", req.kind()));
            0
        });
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&path).unwrap();
        let first: serde_json::Value =
            serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(first["event"], "started");
        assert_eq!(first["detail"], "check_update");
    }

    /// The whole point of the guard: a check that moved a pin is a FAILED
    /// job, loudly, even if everything else about it worked.
    #[test]
    fn a_check_that_broke_the_read_only_guarantee_fails_the_job() {
        let (result, detail, code) = check_update_outcome(
            &["the update check modified /etc/ferrum/flake.lock -- it must be strictly read-only"
                .to_string()],
            Ok(std::path::PathBuf::from("/var/lib/ferrum/jobs/x.update-check.json")),
            "up to date; 4 enabled app(s), 3 excluded",
        );
        assert_eq!(result, "failed");
        assert_eq!(code, 1);
        assert!(detail.contains("flake.lock"), "{detail}");
        // Anti-vacuity: the same call with no violation really does pass.
        let (result, detail, code) = check_update_outcome(
            &[],
            Ok(std::path::PathBuf::from("/var/lib/ferrum/jobs/x.update-check.json")),
            "up to date; 4 enabled app(s), 3 excluded",
        );
        assert_eq!(result, "succeeded");
        assert_eq!(code, 0);
        assert!(detail.contains("x.update-check.json"), "{detail}");
    }

    /// A report nobody can read is not a completed check: ferrumd serves
    /// the document, not the progress stream, so a silent write failure
    /// would leave the operator staring at a successful job with no answer.
    #[test]
    fn a_report_that_could_not_be_written_fails_the_job() {
        let (result, detail, code) =
            check_update_outcome(&[], Err("Permission denied (os error 13)".to_string()), "x");
        assert_eq!(result, "failed");
        assert_eq!(code, 1);
        assert!(detail.contains("Permission denied"), "{detail}");
    }

    /// The exit code is the runner's, not something `run_request` invents --
    /// a dispatched apply that degrades must still surface its own 3.
    #[test]
    fn run_request_returns_the_runners_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let mut progress = progress::Progress::to_path(&dir.path().join("j.jsonl"));
        assert_eq!(run_request(request::Request::Apply { accept_pin_change: None }, &mut progress, |_| 3), 3);
    }

    /// A refused apply never reaches the builder, and says so in the job's
    /// own progress file in the shape the Apply view reads.
    #[test]
    fn a_gated_apply_never_builds_and_names_the_revision_the_retry_must_accept() {
        use ferrum_state::journal::Pin;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.jsonl");
        let mut progress = progress::Progress::to_path(&path);

        let state = pin_gate::classify(
            Some(Pin { rev: "2".repeat(40), nar_hash: "h2".into() }),
            Some(Pin { rev: "1".repeat(40), nar_hash: "h1".into() }),
        );
        let code = run_apply_gated(&state, 7, None, &mut progress, || {
            panic!("the builder must not run for a gated apply")
        });
        assert_eq!(code, 1);

        let lines = std::fs::read_to_string(&path).unwrap();
        let events: Vec<serde_json::Value> =
            lines.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let gate = events
            .iter()
            .find(|e| e["event"] == "pin-gate")
            .expect("the refusal must be its own event, not only the terminal line");
        let detail = gate["detail"].as_str().unwrap();
        let (rev, message) = detail.split_once(": ").expect("`<rev>: <prose>` is the shape the UI splits");
        assert_eq!(rev, "2".repeat(40), "the UI hands this back verbatim as the acknowledgement");
        assert!(message.contains("1111111"), "{message}");
        assert_eq!(events.last().unwrap()["event"], "complete");
        assert!(events.last().unwrap()["detail"].as_str().unwrap().starts_with("failed: "));
    }

    /// The anti-vacuity half: every state that is not an unacknowledged
    /// difference reaches the builder and returns ITS exit code, so the
    /// gate above cannot be satisfied by refusing everything.
    #[test]
    fn an_ungated_apply_reaches_the_builder_and_returns_its_exit_code() {
        use ferrum_state::journal::Pin;
        let old = Pin { rev: "1".repeat(40), nar_hash: "h1".into() };
        let new = Pin { rev: "2".repeat(40), nar_hash: "h2".into() };
        for (label, state, accepted) in [
            ("matching pins", pin_gate::classify(Some(old.clone()), Some(old.clone())), None),
            ("a pin-unknown generation", pin_gate::classify(Some(new.clone()), None), None),
            ("no lock to read", pin_gate::classify(None, Some(old.clone())), None),
            (
                "an acknowledged difference",
                pin_gate::classify(Some(new.clone()), Some(old.clone())),
                Some("2".repeat(40)),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut progress = progress::Progress::to_path(&dir.path().join("j.jsonl"));
            assert_eq!(
                run_apply_gated(&state, 7, accepted.as_deref(), &mut progress, || 3),
                3,
                "{label} must reach the builder and surface its own exit code"
            );
        }
    }

    /// The rollback notice's three real reads, against real files.
    ///
    /// Drives the whole join: `system-<N>-link` resolves the target's
    /// closure, the journal entry claiming that closure carries the pin it
    /// was built from, and the lock beside the flake carries the pin that is
    /// there now.
    #[test]
    fn a_rollback_notice_joins_the_profile_link_the_journal_and_the_lock() {
        use ferrum_state::journal::{self, JournalEntry, Pin};
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles");
        let journal_dir = dir.path().join("journal");
        let closure = dir.path().join("toplevel-gen3");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::create_dir_all(&closure).unwrap();
        std::os::unix::fs::symlink(&closure, profiles.join("system-3-link")).unwrap();
        journal::write(
            &journal_dir,
            &JournalEntry {
                snapshot: "1000-gen2".to_string(),
                generation: 2,
                toplevel: "/nix/store/whatever".to_string(),
                taken_at: "1000".to_string(),
                quiesced: true,
                built_pin: Some(Pin { rev: "1".repeat(40), nar_hash: "sha256-OLD=".into() }),
                built_toplevel: Some(closure.to_string_lossy().into_owned()),
                update_pre_image: false,
            },
        )
        .unwrap();
        let flake_ref = format!("{}#nixosConfigurations.default", dir.path().display());
        // Both halves of the pin are written, because both are compared: a
        // fixture that varied only the revision would have the hashes
        // disagreeing in every row and the "unchanged pin" case below would
        // be a difference after all. (It was, before this took a hash.)
        let lock = |rev: &str, hash: &str| {
            format!(
                r#"{{"nodes":{{"root":{{"inputs":{{"ferrum":"ferrum"}}}},
                   "ferrum":{{"locked":{{"rev":"{rev}","narHash":"{hash}"}}}}}}}}"#
            )
        };

        // The lock has moved on since generation 3 was built.
        std::fs::write(dir.path().join("flake.lock"), lock(&"2".repeat(40), "sha256-NEW=")).unwrap();
        let notice = rollback_pin_notice(3, &profiles, &journal_dir, &flake_ref)
            .expect("a real pin difference must be announced");
        assert!(notice.contains("1111111") && notice.contains("2222222"), "{notice}");

        // The anti-vacuity half, twice over: the identical pin says
        // nothing, and so does a target whose link resolves to a closure no
        // journal entry claims -- which is every generation on a host whose
        // journal predates these fields.
        std::fs::write(dir.path().join("flake.lock"), lock(&"1".repeat(40), "sha256-OLD=")).unwrap();
        assert_eq!(
            rollback_pin_notice(3, &profiles, &journal_dir, &flake_ref),
            None,
            "an unchanged pin must not produce a warning"
        );
        std::fs::write(dir.path().join("flake.lock"), lock(&"2".repeat(40), "sha256-NEW=")).unwrap();
        assert_eq!(
            rollback_pin_notice(9, &profiles, &journal_dir, &flake_ref),
            None,
            "a target with no recorded pin must not produce a warning"
        );
    }

    /// The gate's three real reads, wired together.
    ///
    /// Asserts only the shapes that do not depend on the machine running
    /// the test: `/run/current-system` exists on a NixOS host and not in a
    /// build sandbox or on a developer's Mac, but the journal handed in
    /// here is empty either way, so the running side is unknown in all
    /// three environments. That is the point being pinned -- an unreadable
    /// or silent side degrades to unknown, which `pin_gate::decide` lets
    /// through, rather than to an error that would fail the apply over
    /// bookkeeping.
    #[test]
    fn the_pin_state_degrades_to_unknown_rather_than_failing_the_apply() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("journal");
        let flake_ref = format!("{}#nixosConfigurations.default", dir.path().display());

        // No lock beside the flake, and nothing in the journal.
        assert_eq!(
            pin_state_for_apply(&flake_ref, &journal),
            pin_gate::PinState::Unknown(pin_gate::UnknownSide::Both)
        );

        // A readable lock moves exactly one side, which is also the proof
        // that the on-disk read is really wired to the flake reference it
        // was given rather than returning None unconditionally.
        std::fs::write(
            dir.path().join("flake.lock"),
            r#"{"nodes":{"root":{"inputs":{"ferrum":"ferrum"}},
                "ferrum":{"locked":{"rev":"4444444444444444444444444444444444444444",
                                    "narHash":"sha256-GATE="}}}}"#,
        )
        .unwrap();
        assert_eq!(
            pin_state_for_apply(&flake_ref, &journal),
            pin_gate::PinState::Unknown(pin_gate::UnknownSide::Running),
            "an empty journal leaves the running generation's pin unknown, never disagreeing"
        );
    }

    #[test]
    fn parses_check_update() {
        let cli = Cli::parse_from(["ferrum-apply", "check-update"]);
        assert!(matches!(cli.command, Command::CheckUpdate));
    }

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

    /// The two shapes of `apply`, and the new `confirm-update`.
    #[test]
    fn parses_the_apply_and_confirm_update_subcommands() {
        let plain = Cli::parse_from(["ferrum-apply", "apply"]);
        match plain.command {
            Command::Apply { accept_pin_change } => assert_eq!(accept_pin_change, None),
            other => panic!("expected Apply, got {other:?}"),
        }
        let accepting = Cli::parse_from([
            "ferrum-apply",
            "apply",
            "--accept-pin-change",
            &"2".repeat(40),
        ]);
        match accepting.command {
            Command::Apply { accept_pin_change } => {
                assert_eq!(accept_pin_change.as_deref(), Some("2".repeat(40).as_str()));
            }
            other => panic!("expected Apply, got {other:?}"),
        }
        assert!(matches!(
            Cli::parse_from(["ferrum-apply", "confirm-update"]).command,
            Command::ConfirmUpdate
        ));
    }

    #[test]
    fn parses_preview_migration_subcommand() {
        let cli = Cli::parse_from(["ferrum-apply", "preview-migration"]);
        assert!(matches!(cli.command, Command::PreviewMigration));
    }

    /// The secret VALUE must never be an argument -- it would land in `ps`
    /// and in shell history. Only the name and the flag are.
    #[test]
    fn put_secret_takes_a_name_and_an_optional_replace_flag() {
        let cli = Cli::parse_from(["ferrum-apply", "put-secret", "acme-dns"]);
        match cli.command {
            Command::PutSecret { ref name, replace } => {
                assert_eq!(name, "acme-dns");
                assert!(!replace);
            }
            _ => panic!("expected PutSecret, got {:?}", cli.command),
        }

        let cli = Cli::parse_from(["ferrum-apply", "put-secret", "acme-dns", "--replace"]);
        match cli.command {
            Command::PutSecret { replace, .. } => assert!(replace),
            _ => panic!("expected PutSecret"),
        }
    }

    #[test]
    fn parses_run_request_subcommand() {
        let cli = Cli::parse_from(["ferrum-apply", "run-request", "/tmp/req.json"]);
        match cli.command {
            Command::RunRequest { path } => assert_eq!(path, std::path::PathBuf::from("/tmp/req.json")),
            other => panic!("expected RunRequest, got {other:?}"),
        }
    }

    fn storage_in(dir: &std::path::Path) -> restore_state::StorageConfig {
        restore_state::StorageConfig {
            intent_path: dir.join("var/rollback-intent.json"),
            result_path: dir.join("var/rollback-result.json"),
            failure_marker_path: dir.join("run/ferrum/state-restore-failed"),
        }
    }

    /// The real regression: a failed restore used to be reported to the
    /// operator's SSE stream as "succeeded". This drives the REAL
    /// restore_state::run failure path (a malformed intent, which really
    /// writes the real failure marker) and asserts the progress outcome
    /// derived from it is genuinely a failure.
    #[test]
    fn a_real_failed_restore_is_reported_as_failed_not_succeeded() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage_in(dir.path());
        std::fs::create_dir_all(storage.intent_path.parent().unwrap()).unwrap();
        std::fs::write(&storage.intent_path, "not json").unwrap();

        let had_intent = storage.intent_path.exists();
        restore_state::run("", &storage);

        assert!(storage.failure_marker_path.exists());
        let (result, detail) = restore_state_outcome(&storage, had_intent);
        assert_eq!(result, "failed");
        assert!(
            detail.contains("malformed rollback intent"),
            "the real failure reason must reach the operator, got: {detail}"
        );
    }

    /// A valid intent that cannot be acted on (empty root device) is the
    /// other real failure path -- also reported as a failure, with the real
    /// reason rather than a generic one.
    #[test]
    fn an_unactionable_intent_is_reported_as_failed_with_the_real_reason() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage_in(dir.path());
        std::fs::create_dir_all(storage.intent_path.parent().unwrap()).unwrap();
        std::fs::write(
            &storage.intent_path,
            r#"{"target_generation": 1, "snapshot": "s", "requested_at": "2026-08-20T00:00:00Z"}"#,
        )
        .unwrap();

        let had_intent = storage.intent_path.exists();
        restore_state::run("", &storage);

        let (result, detail) = restore_state_outcome(&storage, had_intent);
        assert_eq!(result, "failed");
        assert!(
            detail.contains("FERRUM_ROOT_DEVICE"),
            "expected the real underlying reason, got: {detail}"
        );
    }

    /// An ordinary boot with nothing pending: no marker is ever written, so
    /// this really is a success -- and says so honestly rather than
    /// claiming a restore happened.
    #[test]
    fn an_ordinary_boot_with_no_pending_restore_reports_success() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage_in(dir.path());

        let had_intent = storage.intent_path.exists();
        restore_state::run("", &storage);

        let (result, detail) = restore_state_outcome(&storage, had_intent);
        assert_eq!(result, "succeeded");
        assert!(detail.contains("no state restore was pending"), "got: {detail}");
    }

    /// A marker left behind by an EARLIER boot's failure still means apps
    /// are held down right now, so this run must not report success.
    #[test]
    fn a_stale_failure_marker_still_reports_failure() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage_in(dir.path());
        std::fs::create_dir_all(storage.failure_marker_path.parent().unwrap()).unwrap();
        std::fs::write(&storage.failure_marker_path, "an earlier boot's failure").unwrap();

        let (result, detail) = restore_state_outcome(&storage, false);
        assert_eq!(result, "failed");
        assert!(detail.contains("an earlier boot's failure"), "got: {detail}");
    }

    /// A marker with no readable reason must still be a failure, not a
    /// success with a confusing empty detail.
    #[test]
    fn an_empty_failure_marker_is_still_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let storage = storage_in(dir.path());
        std::fs::create_dir_all(storage.failure_marker_path.parent().unwrap()).unwrap();
        std::fs::write(&storage.failure_marker_path, "").unwrap();

        let (result, detail) = restore_state_outcome(&storage, true);
        assert_eq!(result, "failed");
        assert!(detail.contains("no reason recorded"), "got: {detail}");
    }

    #[test]
    fn apply_result_maps_to_distinct_exit_codes() {
        assert_eq!(handle_apply_result(Ok(apply::ApplyResult::Succeeded)), 0);
        assert_eq!(
            handle_apply_result(Ok(apply::ApplyResult::Degraded("x".to_string()))),
            3
        );
        assert_eq!(
            handle_apply_result(Ok(apply::ApplyResult::Failed("x".to_string()))),
            1
        );
        assert_eq!(handle_apply_result(Err(anyhow::anyhow!("boom"))), 1);
    }

    /// The one function that composes the whole check -- tripwire, report,
    /// publication, exit code -- and the only place the tripwire's output
    /// is connected to the job's outcome.
    ///
    /// It had no test at all: a mutation that replaced `guard.violations()`
    /// with an empty vector, disconnecting the read-only tripwire from the
    /// job outcome entirely, left the whole suite green. These two tests
    /// are what makes that mutation fail.
    mod check_update_composition {
        use super::*;
        use crate::update_check::{CommandOutput, CommandRunner};
        use std::cell::RefCell;

        const INSTALLED: &str = "1111111111111111111111111111111111111111";
        const CANDIDATE: &str = "2222222222222222222222222222222222222222";

        /// A runner that answers the check's questions, and -- when asked
        /// to -- writes to `flake.nix` while doing it, which is exactly the
        /// event the tripwire exists to catch.
        struct Saboteur {
            writes_to: Option<std::path::PathBuf>,
            calls: RefCell<usize>,
        }

        impl CommandRunner for Saboteur {
            fn run(&self, _program: &str, args: &[String]) -> Result<CommandOutput, String> {
                *self.calls.borrow_mut() += 1;
                if let Some(path) = &self.writes_to {
                    // A pin advanced behind the operator's back: the whole
                    // reason this job is defined by what it must not do.
                    std::fs::write(path, "{ inputs.ferrum.url = \"github:someone/else\"; }\n")
                        .unwrap();
                }
                let joined = args.join(" ");
                let body = if joined.contains("ferrum.apps") {
                    r#"{"sonarr":{"enable":true}}"#.to_string()
                } else if joined.contains("ferrum.schemaVersion") {
                    "2".to_string()
                } else if joined.contains("package.version") {
                    "\"4.0.1\"".to_string()
                } else if joined.contains("ls-remote") {
                    format!("{CANDIDATE}\tHEAD\n")
                } else {
                    serde_json::json!({"lastModified": 200, "revision": CANDIDATE}).to_string()
                };
                Ok(CommandOutput { success: true, stdout: body, stderr: String::new() })
            }
        }

        struct Host {
            _dir: tempfile::TempDir,
            job: CheckUpdateJob,
            progress_path: std::path::PathBuf,
        }

        fn host() -> Host {
            let dir = tempfile::tempdir().unwrap();
            let flake_dir = dir.path().join("etc");
            std::fs::create_dir_all(&flake_dir).unwrap();
            let flake_nix = flake_dir.join("flake.nix");
            std::fs::write(&flake_nix, "{ inputs.ferrum.url = \"github:syms-dev/ferrum\"; }\n")
                .unwrap();
            let flake_lock = flake_dir.join("flake.lock");
            std::fs::write(
                &flake_lock,
                serde_json::json!({
                    "nodes": {
                        "root": {"inputs": {"ferrum": "ferrum"}},
                        "ferrum": {"locked": {"rev": INSTALLED, "lastModified": 100}}
                    },
                    "version": 7
                })
                .to_string(),
            )
            .unwrap();
            let settings_path = dir.path().join("settings.json");
            std::fs::write(&settings_path, r#"{"schemaVersion":2,"apps":{}}"#).unwrap();
            let report_dir = dir.path().join("jobs");
            Host {
                progress_path: dir.path().join("job.jsonl"),
                job: CheckUpdateJob {
                    flake_dir: flake_dir.to_string_lossy().into_owned(),
                    config_attr: "nixosConfigurations.saltbox.config".to_string(),
                    settings_path,
                    flake_nix,
                    flake_lock,
                    // Absent on purpose: these tests are about the job's
                    // composition, and reading the real /run/current-system
                    // would make them agree with the host they run on.
                    journal_dir: dir.path().join("journal-absent"),
                    running_system: dir.path().join("current-system-absent"),
                    report_dir,
                    report_file: "job-1.update-check.json".to_string(),
                    now: 1_758_700_000,
                },
                _dir: dir,
            }
        }

        /// The clean path: a report is published and the job succeeds.
        /// Without this, the failing case below could pass simply because
        /// the composition never succeeds at anything.
        #[test]
        fn a_check_that_touches_nothing_publishes_its_report_and_exits_zero() {
            let h = host();
            let runner = Saboteur { writes_to: None, calls: RefCell::new(0) };
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_check_update_job(&h.job, &runner, &mut progress);

            assert_eq!(code, 0, "a clean check must exit zero");
            assert!(*runner.calls.borrow() > 0, "the check ran no subprocess at all");
            let published = h.job.report_dir.join(&h.job.report_file);
            let body = std::fs::read_to_string(&published).expect("no report was published");
            let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(doc["candidate"]["state"], "update-available");
            let stream = std::fs::read_to_string(&h.progress_path).unwrap();
            assert!(stream.contains("succeeded"), "{stream}");
        }

        /// The case with no second chance: the check moved a protected
        /// file. The tripwire's real output must reach the job outcome --
        /// a non-zero exit, a `failed` progress line, and the violation
        /// recorded in the report's own warnings.
        #[test]
        fn a_check_that_moved_a_protected_file_fails_the_job_with_the_tripwires_own_words() {
            let h = host();
            let before = std::fs::read_to_string(&h.job.flake_nix).unwrap();
            let runner = Saboteur {
                writes_to: Some(h.job.flake_nix.clone()),
                calls: RefCell::new(0),
            };
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_check_update_job(&h.job, &runner, &mut progress);

            // Positive control on the fixture: the file really did move,
            // so a passing tripwire below would be a finding and not an
            // artefact of nothing having happened.
            let after = std::fs::read_to_string(&h.job.flake_nix).unwrap();
            assert_ne!(before, after, "the saboteur did not actually write the file");

            assert_eq!(code, 1, "a broken read-only guarantee must fail the job");
            let stream = std::fs::read_to_string(&h.progress_path).unwrap();
            assert!(stream.contains("failed"), "the job did not report failure: {stream}");
            assert!(
                stream.contains("flake.nix"),
                "the terminal line must name the file that moved: {stream}"
            );
            let body = std::fs::read_to_string(h.job.report_dir.join(&h.job.report_file)).unwrap();
            assert!(
                body.contains("flake.nix"),
                "the published report must carry the violation: {body}"
            );
        }
    }

    /// The update commit, composed end to end: refuse a dirty tree, resolve,
    /// advance the pin, hand off to the ordinary apply, and undo the advance
    /// when nothing was switched.
    ///
    /// Every test here asserts on FILES afterwards as well as on the exit
    /// code, because the two claims this feature actually makes -- flake.nix
    /// is byte-identical, and a failed update leaves no advanced pin behind
    /// -- are claims about files and cannot be made any other way.
    mod update_composition {
        use super::*;
        use crate::update_check::{CommandOutput, CommandRunner};
        use std::cell::RefCell;

        const INSTALLED: &str = "1111111111111111111111111111111111111111";
        const CANDIDATE: &str = "2222222222222222222222222222222222222222";

        fn lock_for(rev: &str, last_modified: i64) -> String {
            serde_json::json!({
                "nodes": {
                    "root": {"inputs": {"ferrum": "ferrum"}},
                    "ferrum": {"locked": {
                        "type": "github", "owner": "syms-dev", "repo": "ferrum",
                        "rev": rev, "narHash": format!("sha256-{rev}="),
                        "lastModified": last_modified}}
                },
                "version": 7
            })
            .to_string()
        }

        /// A runner that answers `git status`, `git ls-remote` and
        /// `nix flake metadata`, and performs the real side effect of
        /// `nix flake lock --update-input`: it rewrites the lock.
        struct Runner {
            flake_lock: std::path::PathBuf,
            /// What `git status --porcelain` says. Empty is a clean tree.
            dirty: String,
            /// The revision `git ls-remote` reports for the tracked ref.
            remote_rev: String,
            /// The revision the lock ends up pinning after the advance.
            lands_on: String,
            argvs: RefCell<Vec<String>>,
        }

        impl CommandRunner for Runner {
            fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
                let joined = args.join(" ");
                self.argvs.borrow_mut().push(format!("{program} {joined}"));
                let stdout = if joined.contains("status") {
                    self.dirty.clone()
                } else if joined.contains("ls-remote") {
                    format!("{}\tHEAD\n", self.remote_rev)
                } else if joined.contains("flake lock") {
                    std::fs::write(&self.flake_lock, lock_for(&self.lands_on, 300)).unwrap();
                    String::new()
                } else {
                    // nix flake metadata, for the ordering comparison.
                    serde_json::json!({"lastModified": 300, "revision": self.remote_rev})
                        .to_string()
                };
                Ok(CommandOutput { success: true, stdout, stderr: String::new() })
            }
        }

        struct Host {
            _dir: tempfile::TempDir,
            job: UpdateJob,
            progress_path: std::path::PathBuf,
            nix_bytes: Vec<u8>,
            lock_bytes: Vec<u8>,
        }

        fn host() -> Host {
            let dir = tempfile::tempdir().unwrap();
            let flake_dir = dir.path().join("etc");
            std::fs::create_dir_all(&flake_dir).unwrap();
            let flake_nix = flake_dir.join("flake.nix");
            std::fs::write(&flake_nix, "{ inputs.ferrum.url = \"github:syms-dev/ferrum\"; }\n")
                .unwrap();
            let flake_lock = flake_dir.join("flake.lock");
            std::fs::write(&flake_lock, lock_for(INSTALLED, 100)).unwrap();
            Host {
                progress_path: dir.path().join("job.jsonl"),
                nix_bytes: std::fs::read(&flake_nix).unwrap(),
                lock_bytes: std::fs::read(&flake_lock).unwrap(),
                job: UpdateJob {
                    flake_ref: format!(
                        "{}#nixosConfigurations.saltbox.config.system.build.toplevel",
                        flake_dir.display()
                    ),
                    flake_dir: flake_dir.to_string_lossy().into_owned(),
                    flake_nix,
                    flake_lock,
                    now: 1_758_700_000,
                },
                _dir: dir,
            }
        }

        impl Host {
            fn runner(&self) -> Runner {
                Runner {
                    flake_lock: self.job.flake_lock.clone(),
                    dirty: String::new(),
                    remote_rev: CANDIDATE.to_string(),
                    lands_on: CANDIDATE.to_string(),
                    argvs: RefCell::new(Vec::new()),
                }
            }
            fn flake_nix_is_byte_identical(&self) -> bool {
                std::fs::read(&self.job.flake_nix).unwrap() == self.nix_bytes
            }
            fn flake_lock_is_byte_identical(&self) -> bool {
                std::fs::read(&self.job.flake_lock).unwrap() == self.lock_bytes
            }
            fn stream(&self) -> String {
                std::fs::read_to_string(&self.progress_path).unwrap()
            }
        }

        /// The clean path. Without it every refusal below could pass on a
        /// composition that refuses everything.
        #[test]
        fn a_newer_candidate_is_advanced_applied_and_reported_as_a_generation() {
            let h = host();
            let runner = h.runner();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |flake_ref| {
                    assert_eq!(flake_ref, h.job.flake_ref, "the apply gets the host's own ref");
                    Ok(apply::ApplyResult::Succeeded)
                },
                {
                    let n = RefCell::new(vec![10u32, 9]); // popped: 9 before, 10 after
                    move || n.borrow_mut().pop()
                },
            );

            assert_eq!(code, 0);
            assert!(!h.flake_lock_is_byte_identical(), "the lock is the file an update writes");
            assert!(h.flake_nix_is_byte_identical(), "flake.nix is never written");
            let stream = h.stream();
            assert!(stream.contains("succeeded"), "{stream}");
            assert!(stream.contains("generation 10"), "{stream}");
            assert!(stream.contains("2222222"), "the applied revision is named: {stream}");
        }

        /// R4's last edge case, and the one the spec singles out as the
        /// thing that ships as a lie in a status line. `apply::run` returns
        /// early on an unchanged closure -- no preflight, no snapshot, no
        /// journal entry, no generation -- and the operator must be told
        /// exactly that.
        #[test]
        fn an_advance_that_builds_the_running_closure_says_no_change_nothing_to_apply() {
            let h = host();
            let runner = h.runner();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| Ok(apply::ApplyResult::Succeeded),
                || Some(9), // the generation number never moved
            );

            assert_eq!(code, 0, "nothing failed -- there was simply nothing to apply");
            let stream = h.stream();
            assert!(
                stream.contains("no change — nothing to apply"),
                "the operator must be told exactly this: {stream}"
            );
            assert!(
                !stream.contains("generation 9"),
                "no generation was created, so none may be claimed: {stream}"
            );
        }

        /// And the no-change wording is not what a real generation gets --
        /// without this, a composition that always said "no change" would
        /// pass the test above.
        #[test]
        fn the_no_change_wording_is_never_used_for_a_real_generation() {
            assert!(update_detail(&Produced::Generation(11), CANDIDATE).contains("generation 11"));
            assert!(!update_detail(&Produced::Generation(11), CANDIDATE).contains("no change"));
            assert!(update_detail(&Produced::NoChange, CANDIDATE).contains("no change — nothing to apply"));
            // An unreadable generation number is its own answer, never the
            // no-change one: "we could not look" and "there was nothing" are
            // different facts, the same distinction CandidateState draws.
            let unknown = update_detail(&Produced::Unknown, CANDIDATE);
            assert!(unknown.contains("unknown"), "{unknown}");
            assert!(!unknown.contains("no change"), "{unknown}");
            assert_eq!(produced(Some(4), Some(5)), Produced::Generation(5));
            assert_eq!(produced(Some(4), Some(4)), Produced::NoChange);
            assert_eq!(produced(None, Some(5)), Produced::Unknown);
            assert_eq!(produced(Some(4), None), Produced::Unknown);
        }

        /// DA-5: a machine-written flake.lock in a dirty tree is one
        /// `git checkout` away from being silently reverted, after which
        /// the next ordinary apply downgrades the whole host.
        #[test]
        fn a_dirty_flake_directory_refuses_before_anything_privileged_runs() {
            let h = host();
            let mut runner = h.runner();
            runner.dirty = " M settings.json\n?? scratch.nix\n".to_string();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| panic!("the apply must not run on a dirty tree"),
                || Some(9),
            );

            assert_eq!(code, 1);
            assert!(h.flake_lock_is_byte_identical());
            assert!(h.flake_nix_is_byte_identical());
            let stream = h.stream();
            assert!(stream.contains("settings.json"), "the files are named: {stream}");
            assert_eq!(
                runner.argvs.borrow().len(),
                1,
                "the only subprocess is the question itself: {:?}",
                runner.argvs.borrow()
            );
        }

        /// Monotonicity enforced at apply, not only at discovery (DA-1).
        #[test]
        fn a_candidate_that_is_already_installed_is_reported_as_nothing_to_apply() {
            let h = host();
            let mut runner = h.runner();
            runner.remote_rev = INSTALLED.to_string();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| panic!("there is nothing to apply"),
                || Some(9),
            );

            assert_eq!(code, 0, "being up to date is not a failure");
            assert!(h.flake_lock_is_byte_identical(), "nothing is written when nothing moves");
            let stream = h.stream();
            assert!(stream.contains("nothing to apply"), "{stream}");
        }

        /// A candidate that resolved but could not be shown to be newer is
        /// refused, not applied -- `OrderUnknown` must never behave like
        /// `UpdateAvailable`. Here the lock's own lastModified sits in the
        /// future, which is the real way this happens.
        #[test]
        fn a_candidate_that_cannot_be_shown_to_be_newer_is_refused() {
            let h = host();
            std::fs::write(&h.job.flake_lock, lock_for(INSTALLED, 9_000_000_000)).unwrap();
            let lock_bytes = std::fs::read(&h.job.flake_lock).unwrap();
            let runner = h.runner();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| panic!("an unordered candidate must never be applied"),
                || Some(9),
            );

            assert_eq!(code, 1);
            assert_eq!(std::fs::read(&h.job.flake_lock).unwrap(), lock_bytes);
            assert!(h.stream().contains("refusing to update"), "{}", h.stream());
        }

        /// A build failure at the candidate pin leaves an advanced lock that
        /// the next unrelated settings apply would silently build from --
        /// the exact drift R8 names. It is undone.
        #[test]
        fn an_apply_that_failed_puts_the_pin_back() {
            let h = host();
            let runner = h.runner();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| Ok(apply::ApplyResult::Failed("nix build failed: hash mismatch".to_string())),
                || Some(9),
            );

            assert_eq!(code, 1);
            assert!(
                h.flake_lock_is_byte_identical(),
                "a failed update must leave no advanced pin behind"
            );
            assert!(h.flake_nix_is_byte_identical());
            let stream = h.stream();
            assert!(stream.contains("hash mismatch"), "nix's own words reach the operator: {stream}");
            assert!(stream.contains("put back"), "{stream}");
        }

        /// An apply that gave up part-way is NOT undone, and the operator is
        /// told that in so many words. `apply::run` raises this after
        /// `nix-env --set` as readily as before it ("apply failed
        /// mid-sequence"), so whether the host switched is genuinely
        /// unknown here -- and putting the pin back under a system that did
        /// switch would be the same disagreement pointed the other way.
        #[test]
        fn an_apply_that_gave_up_mid_sequence_leaves_the_pin_and_says_so() {
            let h = host();
            let runner = h.runner();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| Err(anyhow::anyhow!("apply failed mid-sequence (apps have been restarted)")),
                || Some(9),
            );

            assert_eq!(code, 1);
            assert!(
                !h.flake_lock_is_byte_identical(),
                "an ambiguous outcome must not be guessed at by reverting"
            );
            let stream = h.stream();
            assert!(stream.contains("mid-sequence"), "the real error reaches the operator: {stream}");
            assert!(
                stream.contains("NOT been put back"),
                "the operator must be told the pin stands: {stream}"
            );
        }

        /// A DEGRADED update did switch, so the pin stays: reverting it
        /// under a running generation would make the lock disagree with
        /// what is actually installed. Reported in the same vocabulary a
        /// degraded settings apply uses, with the same exit code 3.
        #[test]
        fn a_degraded_update_keeps_the_pin_and_speaks_the_ordinary_vocabulary() {
            let h = host();
            let runner = h.runner();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| {
                    Ok(apply::ApplyResult::Degraded(
                        "one or more managed units failed to become active".to_string(),
                    ))
                },
                {
                    let n = RefCell::new(vec![10u32, 9]); // popped: 9 before, 10 after
                    move || n.borrow_mut().pop()
                },
            );

            assert_eq!(code, 3, "the same code a degraded settings apply exits with");
            assert!(!h.flake_lock_is_byte_identical(), "the host switched; the pin stands");
            let stream = h.stream();
            assert!(stream.contains("degraded"), "{stream}");
            assert!(
                stream.contains("one or more managed units failed to become active"),
                "the same words a degraded settings apply uses: {stream}"
            );
        }

        /// DA-1 at the composition level: `nix` re-resolves the ref itself,
        /// so a push landing mid-job would otherwise apply a revision the
        /// operator never saw.
        #[test]
        fn an_advance_that_landed_elsewhere_is_refused_and_never_applied() {
            let h = host();
            let mut runner = h.runner();
            runner.lands_on = "3333333333333333333333333333333333333333".to_string();
            let mut progress = progress::Progress::to_path(&h.progress_path);

            let code = run_update_job(
                &h.job,
                &runner,
                &mut progress,
                |_| panic!("a revision nobody reviewed must never be applied"),
                || Some(9),
            );

            assert_eq!(code, 1);
            assert!(h.flake_lock_is_byte_identical());
            assert!(h.stream().contains("3333333"), "{}", h.stream());
        }
    }
}
