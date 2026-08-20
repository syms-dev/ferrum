use clap::{Parser, Subcommand};

mod apply;
mod generations;
mod journal;
mod preflight;
mod restore_state;

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
            handle_apply_result(apply::run(&flake_ref, &storage))
        }
        Command::Rollback { to: _ } => {
            eprintln!("rollback: not yet implemented");
            1
        }
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
