use clap::{Parser, Subcommand};

mod preflight;

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
