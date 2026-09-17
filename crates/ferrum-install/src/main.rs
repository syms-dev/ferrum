//! `ferrum-install` -- takes a machine you can SSH into as root and turns it
//! into a working ferrum host.
//!
//! It replaces `docs/INSTALL.md`'s eight manual steps: identifying disks by
//! `/dev/disk/by-id/`, determining the firmware mode, hand-editing twelve
//! placeholders across the host template, generating a hardware
//! configuration, installing once with no apps, keeping a second settings
//! document alongside, and swapping it in afterwards.
//!
//! It ships as a Docker image so that Docker is the only thing the
//! operator's own machine needs (see the Phase 1.6a spec, DEC-02), with the
//! heavy x86_64 build happening on the target itself via nixos-anywhere's
//! remote build rather than under emulation here.
//!
//! This binary is deliberately staged: the destructive step is not the last
//! step, so its progress is recorded and it is resumable (spec R7). What is
//! implemented so far is the part that runs before anything is contacted.

mod preconditions;

use clap::Parser;

/// Install ferrum onto a target machine.
#[derive(Parser, Debug)]
#[command(name = "ferrum-install")]
#[command(about = "Install ferrum onto a bare machine over SSH", long_about = None)]
struct Cli {
    /// The machine to install onto, as `root@host`. nixos-anywhere replaces
    /// the entire OS, so this must be root.
    target: String,

    /// Directory holding the generated host repository. Bind-mounted from
    /// the operator's machine so it outlives the container.
    #[arg(long, default_value = preconditions::DEFAULT_HOST_DIR)]
    host_dir: std::path::PathBuf,

    /// Read-only mount holding the operator's SSH keys.
    #[arg(long, default_value = preconditions::DEFAULT_SSH_DIR)]
    ssh_dir: std::path::PathBuf,

    /// Discard any existing install state and start over, re-running the
    /// disk confirmation in full. Never implied by a stale directory: a
    /// resume that silently restarted would re-run the destructive step.
    #[arg(long)]
    fresh: bool,
}

fn main() {
    let cli = Cli::parse();

    let agent_sock = std::env::var("SSH_AUTH_SOCK").ok();
    let pre = match preconditions::check_in(
        &cli.target,
        &cli.host_dir,
        &cli.ssh_dir,
        agent_sock.as_deref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ferrum-install: {e}");
            std::process::exit(1);
        }
    };

    // Only the credential's *kind and location* are ever printed. The key
    // itself is never read by this process (see preconditions::find_ssh_auth).
    let auth = match &pre.ssh_auth {
        preconditions::SshAuth::Agent(p) => format!("ssh agent at {}", p.display()),
        preconditions::SshAuth::Key(p) => format!("key {}", p.display()),
    };
    println!("target:        {}", pre.target);
    println!("host repo:     {}", pre.host_dir.display());
    println!("credentials:   {auth}");
    if cli.fresh {
        println!("mode:          --fresh (existing install state will be discarded)");
    }

    eprintln!(
        "\nferrum-install: preconditions pass. The remaining phases (inventory, \n\
         confirmation, generation, preflight, install, stage 2, verification) \n\
         are not implemented yet -- see the Phase 1.6a story breakdown."
    );
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// R1 A3: no target argument means usage and a non-zero exit, with
    /// nothing contacted. `try_parse_from` returning an error is what
    /// produces both.
    #[test]
    fn no_target_is_a_usage_error() {
        let err = Cli::try_parse_from(["ferrum-install"]).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "{err}"
        );
    }

    #[test]
    fn the_defaults_are_the_documented_mount_points() {
        let cli = Cli::parse_from(["ferrum-install", "root@saltbox"]);
        assert_eq!(cli.target, "root@saltbox");
        assert_eq!(
            cli.host_dir,
            std::path::PathBuf::from(preconditions::DEFAULT_HOST_DIR)
        );
        assert_eq!(
            cli.ssh_dir,
            std::path::PathBuf::from(preconditions::DEFAULT_SSH_DIR)
        );
        assert!(!cli.fresh, "--fresh must never be the default");
    }

    #[test]
    fn fresh_is_opt_in() {
        let cli = Cli::parse_from(["ferrum-install", "root@saltbox", "--fresh"]);
        assert!(cli.fresh);
    }

    #[test]
    fn the_mounts_are_overridable_for_testing_outside_a_container() {
        let cli = Cli::parse_from([
            "ferrum-install",
            "root@saltbox",
            "--host-dir",
            "/tmp/h",
            "--ssh-dir",
            "/tmp/s",
        ]);
        assert_eq!(cli.host_dir, std::path::PathBuf::from("/tmp/h"));
        assert_eq!(cli.ssh_dir, std::path::PathBuf::from("/tmp/s"));
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
