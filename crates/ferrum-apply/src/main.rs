use clap::{Parser, Subcommand};

mod apply;
mod dns_reconcile;
mod gc;
mod preflight;
mod progress;
mod put_secret;
mod request;
mod restore_state;
mod rollback;
mod secrets;
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

fn run_apply() -> i32 {
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
    };
    let flake_ref = std::env::var("FERRUM_FLAKE_REF")
        .unwrap_or_else(|_| "/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel".to_string());
    handle_apply_result(apply::run(&flake_ref, &storage))
}

fn run_rollback(to: u32) -> i32 {
    let journal_dir = std::env::var("FERRUM_JOURNAL_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/journal".to_string());
    let intent_path = std::env::var("FERRUM_ROLLBACK_INTENT_PATH")
        .unwrap_or_else(|_| "/var/lib/ferrum/rollback-intent.json".to_string());
    let snapshot_dir = std::env::var("FERRUM_SNAPSHOT_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/snapshots".to_string());
    match rollback::run(
        to,
        std::path::Path::new(&journal_dir),
        std::path::Path::new(&intent_path),
        std::path::Path::new(&snapshot_dir),
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

/// Runs the read-only update check and leaves its report where ferrumd can
/// read it.
///
/// Instrumented through `progress::Progress` -- unlike
/// `run_preview_migration`, which is CLI-only -- because this one is
/// dispatched as a job and `GET /api/jobs` renders its stream.
///
/// # Returns
/// A process exit code: 0 when a report was produced and written, 1 when it
/// could not be, or when the read-only guarantee was broken.
fn run_check_update() -> i32 {
    let mut progress = progress::Progress::open();
    let flake_ref = std::env::var("FERRUM_FLAKE_REF").unwrap_or_else(|_| {
        "/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel".to_string()
    });
    let (flake_dir, config_attr) = update_check::split_flake_ref(&flake_ref);
    let settings_path = std::env::var("FERRUM_SETTINGS_PATH")
        .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
    let flake_nix = std::path::Path::new(&flake_dir).join("flake.nix");
    let flake_lock = std::path::Path::new(&flake_dir).join("flake.lock");

    // Captured BEFORE the first subprocess, released after the last: the
    // window this covers is the whole check.
    let guard = update_check::ReadOnlyGuard::capture(&[&flake_nix, &flake_lock]);
    progress.event(
        "check-update",
        "reading this host's resolved configuration -- nothing is written",
    );

    let inputs = update_check::CheckInputs {
        flake_dir: &flake_dir,
        config_attr: &config_attr,
        settings_path: std::path::Path::new(&settings_path),
        flake_nix: &flake_nix,
        flake_lock: &flake_lock,
        now: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let mut report = update_check::build_report(&inputs, &update_check::RealRunner);

    let violations = guard.violations();
    report.warnings.extend(violations.iter().cloned());

    let job_id = std::env::var("FERRUM_JOB_ID").ok();
    let written = update_check::write_report(
        &update_check::report_dir(),
        &update_check::report_file_name(job_id.as_deref()),
        &report,
    )
    .map_err(|e| e.to_string());

    // stdout carries the whole document, so a bare `ferrum-apply
    // check-update` over SSH is useful on its own -- the same way
    // `preview-migration` prints its summary.
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
    let marker = std::path::PathBuf::from(
        std::env::var("FERRUM_STATE_DIR").unwrap_or_else(|_| "/var/lib/ferrum/state".to_string()),
    )
    .join("dns-updater-last-success");
    let outcome = dns_reconcile::run(
        config,
        &dns_reconcile::cloudflare_client,
        &dns_reconcile::authoritative_verifier,
    );
    reconcile_dns_exit(outcome, &marker, std::time::SystemTime::now())
}

/// Turns a reconcile outcome into output and an exit code.
///
/// Exit codes follow `handle_apply_result`'s convention so a unit or future
/// automation can tell the cases apart without parsing text: **0** clean,
/// **3** reconciled but something is wrong, **1** could not reconcile at
/// all.
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
            return 1;
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
        Command::Apply => run_apply(),
        Command::Rollback { to } => run_rollback(to),
        Command::RestoreState => run_restore_state(),
        Command::Gc => run_gc(),
        Command::PreviewMigration => run_preview_migration(),
        Command::CheckUpdate => run_check_update(),
        Command::ReconcileDns { config } => run_reconcile_dns(&config),
        Command::PutSecret { name, replace } => run_put_secret(&name, replace),
        Command::RunRequest { path } => match request::read_request(&path) {
            Ok(req) => run_request(req, &mut progress::Progress::open(), |req| match req {
                request::Request::Preflight => run_preflight(),
                request::Request::Apply => run_apply(),
                request::Request::Rollback { to } => run_rollback(to),
                request::Request::RestoreState => run_restore_state(),
                request::Request::Gc => run_gc(),
                request::Request::CheckUpdate => run_check_update(),
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
        assert_eq!(run_request(request::Request::Apply, &mut progress, |_| 3), 3);
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
}
