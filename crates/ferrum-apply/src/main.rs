use clap::{Parser, Subcommand};

mod apply;
mod generations;
mod journal;
mod preflight;
mod progress;
mod request;
mod restore_state;
mod rollback;
mod secrets;

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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Preflight => run_preflight(),
        Command::Apply => run_apply(),
        Command::Rollback { to } => run_rollback(to),
        Command::RestoreState => run_restore_state(),
        Command::Gc => {
            eprintln!("gc: not yet implemented");
            1
        }
        Command::RunRequest { path } => match request::read_request(&path) {
            Ok(request::Request::Preflight) => run_preflight(),
            Ok(request::Request::Apply) => run_apply(),
            Ok(request::Request::Rollback { to }) => run_rollback(to),
            Ok(request::Request::RestoreState) => run_restore_state(),
            Ok(request::Request::Gc) => {
                eprintln!("gc: not yet implemented via run-request");
                // Still writes a terminal progress line: a job ferrumd
                // dispatched must always end its own stream, even when the
                // answer is "this kind isn't implemented yet".
                progress::Progress::open().complete("failed", "gc is not yet implemented");
                1
            }
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
