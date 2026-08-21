use clap::{Parser, Subcommand};

mod apply;
mod generations;
mod journal;
mod preflight;
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let exit_code = match cli.command {
        Command::Preflight => {
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
            match preflight::run(
                std::path::Path::new(&state_dir),
                std::path::Path::new(&snapshot_dir),
                min_free_gib,
                std::path::Path::new(&failure_marker_path),
            ) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("preflight failed: {e}");
                    1
                }
            }
        }
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
                    .unwrap_or_else(|_| secrets::DEFAULT_HOST_KEY_PUB.to_string())
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
        Command::Rollback { to } => {
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
        Command::RestoreState => {
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
            restore_state::run(&root_device, &storage);
            0 // always exits 0 -- see Global Constraints
        }
        Command::Gc => {
            eprintln!("gc: not yet implemented");
            1
        }
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
